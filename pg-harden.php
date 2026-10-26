#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * pg-harden 0.3.2
 * Checks a PostgreSQL instance against a data-driven rule catalog, writes a change plan
 * and compares before/after reports.
 *
 * check/plan/verify/client write nothing to the server by design (apply/rollback are the only writers, see
 * src/Apply.php): every check runs inside its own
 * BEGIN TRANSACTION READ ONLY … ROLLBACK, as a single server-side prepared statement
 * (no multi-statement SQL), with search_path = pg_catalog, pg_temp. The rule catalog is
 * trusted input (it ships with the tool); everything read from the server is not.
 * Behind a transaction-pooling PgBouncer session settings are not reliable — connect directly.
 *
 * usage:
 *   php pg-harden.php client [--user=ACCOUNT] [--scan=DIR,DIR] [--format=text|json|html] [--out=FILE]
 *   php pg-harden.php check  [connection] [--format=text|json|html] [--out=FILE]
 *   php pg-harden.php plan   [connection] --dir=NEW_OR_EMPTY_DIR
 *   php pg-harden.php verify [connection] --previous=report.json [--format=...] [--out=FILE]
 *   php pg-harden.php apply  [connection] [--rules=ID,..] [--include-confirm=ID,..] [--execute --dir=NEW_DIR [--yes]]
 *   php pg-harden.php rollback [connection] --dir=APPLY_JOURNAL_DIR
 *   php pg-harden.php rules
 *
 * connection: --host --port --user --dbname (entry database, default postgres) --sslmode
 *             --databases=a,b (restrict database-scoped rules)
 *             Unset host/port fall back to libpq (PGHOST, PGPORT, socket). Remote hosts default
 *             to sslmode=require.
 * password:   never on the command line; libpq reads PGPASSWORD or the pgpass file.
 *
 * exit codes: 0 no findings · 1 findings · 3 no findings, but checks incomplete · 2 abort
 * requires:   PHP 8.3+ with pdo_pgsql and mbstring
 *
 * MIT License, Copyright (c) 2026 Frank Glück (Glück IT) — see LICENSE. Provided "as is", without warranty.
 * Results and plans are suggestions: review them and test every change before applying it to production.
 */

const PG_HARDEN_VERSION = '0.3.2';

require_once __DIR__ . '/src/Os.php';
require_once __DIR__ . '/src/Client.php';
require_once __DIR__ . '/src/Apply.php';

/** Verbatim from the concept ("Rechtlicher Rahmen und bestimmungsgemäße Verwendung"); same text in README, --help and the notices block at the end of the report. */
const LEGAL_NOTICE = 'pg-harden ist zur Härtung eigener oder ausdrücklich beauftragter Systeme bestimmt. '
  . 'Die Passwortprüfung liest pg_authid nur mit Superuser-Recht, rechnet eine kleine, fest umrissene Liste '
  . 'naheliegender Kandidaten sowie optional eine vom Betreiber bereitgestellte, auf 100 Einträge begrenzte Liste '
  . 'betriebsspezifischer Begriffe nach (keine Wörterbücher, kein Brute-Force), erzeugt keine Fehlanmeldungen '
  . 'und gibt nie ein Passwort aus — nur die Tatsache, dass eine Rolle einen Wert aus der Prüfliste verwendet. '
  . 'Der Client-Modus mit --user liest Dateien und Umgebungen anderer Benutzerkonten und setzt Administrator- '
  . 'bzw. root-Rechte und die Berechtigung voraus, diese Konten zu prüfen; gefundene Geheimnisse erscheinen nur '
  . 'mit Fundstelle und Zeile. Berichte können rollenbezogene und damit personenbeziehbare Befunde enthalten: '
  . 'vertraulich behandeln, nur zur Behebung verwenden, zeitnah löschen; wo Rollen Beschäftigten zugeordnet sind, '
  . 'Datenschutz und Mitbestimmung beachten. Eine Nutzung auf fremden Systemen oder Konten ohne Berechtigung ist '
  . 'bestimmungswidrig.';

const MAPPING_DISCLAIMER = 'Die Zuordnung zeigt nur das Ergebnis der aufgeführten technischen Prüfregeln. '
  . 'Sie ist keine Aussage darüber, ob die Anforderung der Norm erfüllt ist; organisatorische und weitere '
  . 'technische Anteile sind nicht geprüft.';

const PLAN_WARNING = 'Automatisch erzeugter Vorschlag. Auswirkungen auf Anwendungen vor dem Ausführen in einer Testumgebung prüfen.';

const RESPONSIBILITY_NOTICE = 'Ohne Gewähr (MIT-Lizenz). Prüfergebnisse und Pläne sind Vorschläge: Befunde fachlich bewerten, '
  . 'jede Änderung selbst prüfen und vor dem Einsatz in Produktion testen. Ein Lauf ohne Befund heißt nur, dass die '
  . 'Regeln des Katalogs nichts gefunden haben — nicht, dass die Instanz sicher ist.';

final class HardenException extends RuntimeException {}

/**
 * Output of the writing commands (apply, rollback). A closed reader (… | head) must never stop them halfway — a rollback
 * killed between "file restored" and "reloaded" leaves the server running on a configuration that is no longer on disk.
 * Writes therefore fail quietly — on stdout and stderr; SIGPIPE is ignored in App::main where pcntl exists (Windows has no SIGPIPE).
 * Read-only commands go through the same path, so "check | head" ends with the exit code of the check, not with an error.
 */
final class Out
{
  public static function write(string $s): void
  {
    @fwrite(STDOUT, $s);
  }

  public static function err(string $s): void
  {
    @fwrite(STDERR, $s);
  }
}

/** Everything that comes from the server is untrusted text: names may contain any character except NUL. */
final class Text
{
  // C0/C1 controls, line/paragraph separators and format characters (bidi overrides, zero-width, BOM).
  private const CONTROL = '/[\p{Cc}\p{Cf}\x{2028}\x{2029}]/u';

  public static function hasControl(?string $s): bool
  {
    return $s !== null && (!mb_check_encoding($s, 'UTF-8') || preg_match(self::CONTROL, $s) === 1);
  }

  /** Visible, single-line representation for terminal, Markdown and SQL comments. */
  public static function printable(?string $s): string
  {
    $s = mb_scrub((string) $s, 'UTF-8');
    return (string) preg_replace_callback(self::CONTROL, fn($m) => sprintf('\\u{%X}', mb_ord($m[0], 'UTF-8')), $s);
  }

  /** Code span for MANUELL.md: no Markdown or HTML is interpreted inside, fence longer than any backtick run. */
  public static function markdown(?string $s): string
  {
    $s = self::printable($s);
    preg_match_all('/`+/', $s, $runs);
    $fence = str_repeat('`', max(array_map('strlen', $runs[0] ?: [''])) + 1);
    return $fence . ' ' . $s . ' ' . $fence;
  }

  /**
   * SQL the server hands back for the plan (fix_sql/rollback_sql) must be one plain statement:
   * outside quotes no backslash (psql meta-commands), no colon (psql variables), exactly one
   * semicolon at the very end. Protects against a server that controls its own answers.
   */
  public static function isSafeStatement(?string $sql): bool
  {
    if ($sql === null) {
      return true;
    }
    if (self::hasControl($sql)) {
      return false;
    }
    $quote = null;
    $semicolons = 0;
    $len = strlen($sql);
    for ($i = 0; $i < $len; $i++) {
      $ch = $sql[$i];
      if ($quote !== null) {
        if ($ch === $quote) {
          if ($i + 1 < $len && $sql[$i + 1] === $quote) {
            $i++;
          } else {
            $quote = null;
          }
        }
        continue;
      }
      if ($ch === '"' || $ch === "'") {
        // E'…' (backslash escapes) and U&'…' are not understood by this scanner: refuse them.
        if ($ch === "'" && $i > 0 && strpbrk($sql[$i - 1], 'EeUu&') !== false) {
          return false;
        }
        if ($ch === '"' && $i > 1 && strtolower(substr($sql, $i - 2, 2)) === 'u&') {
          return false; // U&"…" hides characters in an identifier behind escapes
        }
        $quote = $ch;
      } elseif ($ch === '\\' || $ch === ':' || $ch === '$') {
        return false;
      } elseif (($ch === '-' && ($sql[$i + 1] ?? '') === '-') || ($ch === '/' && ($sql[$i + 1] ?? '') === '*')) {
        return false;
      } elseif ($ch === ';') {
        $semicolons++;
        if ($i !== $len - 1) {
          return false;
        }
      }
    }
    return $quote === null && $semicolons === 1;
  }

  /** $ascii = true for stdout: escapes every non-ASCII character, so no control sequence reaches a terminal. */
  public static function json(mixed $data, bool $ascii = false): string
  {
    $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;
    try {
      return json_encode($data, $ascii ? $flags : $flags | JSON_UNESCAPED_UNICODE) . "\n";
    } catch (JsonException $e) {
      throw new HardenException('JSON-Ausgabe fehlgeschlagen: ' . $e->getMessage());
    }
  }
}

final class Files
{
  /** $exclusive: create only, never overwrite or follow a symlink (O_EXCL) — used for plan files. */
  public static function write(string $file, string $content, bool $exclusive = false): void
  {
    if (is_link($file)) {
      throw new HardenException("$file ist ein symbolischer Link — wird nicht überschrieben.");
    }
    $fh = @fopen($file, $exclusive ? 'x' : 'w');
    if ($fh === false) {
      throw new HardenException("$file konnte nicht angelegt werden" . ($exclusive ? ' (existiert bereits?)' : '') . '.');
    }
    $ok = fwrite($fh, $content) === strlen($content);
    Fs::attempt(fn() => fsync($fh));
    $ok = fclose($fh) && $ok;
    if (!$ok) {
      throw new HardenException("$file konnte nicht vollständig geschrieben werden.");
    }
    @chmod($file, 0600);
  }

  /** Plan directories must be new or empty: stale harden_*.sql from an earlier run must never be executed by mistake. */
  public static function prepareDir(string $dir): void
  {
    if (is_link($dir)) {
      throw new HardenException("$dir ist ein symbolischer Link.");
    }
    if (is_dir($dir)) {
      if ((scandir($dir) ?: []) !== ['.', '..']) {
        throw new HardenException("$dir ist nicht leer. Für jeden Plan ein neues Verzeichnis verwenden.");
      }
      if (DIRECTORY_SEPARATOR === '/' && (fileperms($dir) & 0022) !== 0) {
        throw new HardenException("$dir ist für Gruppe oder andere beschreibbar.");
      }
      // The owner of the directory could replace plan files after the run, whatever their mode.
      if (function_exists('posix_geteuid') && fileowner($dir) !== posix_geteuid()) {
        throw new HardenException("$dir gehört einem anderen Benutzer. Ein neues Verzeichnis angeben.");
      }
      return;
    }
    if (!@mkdir($dir, 0700, true)) {
      throw new HardenException("Verzeichnis $dir lässt sich nicht anlegen.");
    }
  }
}

final class Options
{
  private const VALUED = ['host', 'port', 'user', 'dbname', 'sslmode', 'databases', 'format', 'out', 'dir', 'previous', 'scan', 'rules', 'include-confirm', 'extra-candidates'];
  private const FLAGS = ['help', 'execute', 'yes'];

  public string $command = '';
  private array $values = [];

  public static function parse(array $argv): self
  {
    $o = new self();
    foreach (array_slice($argv, 1) as $arg) {
      if (str_starts_with($arg, '--')) {
        $pair = explode('=', substr($arg, 2), 2);
        if (!in_array($pair[0], self::VALUED, true) && !in_array($pair[0], self::FLAGS, true) && $pair[0] !== 'password') {
          throw new HardenException('Unbekannte Option --' . Text::printable($pair[0]) . ' (siehe --help).');
        }
        if (in_array($pair[0], self::FLAGS, true) && isset($pair[1])) {
          throw new HardenException("--{$pair[0]} ist ein Schalter und nimmt keinen Wert.");
        }
        if (in_array($pair[0], self::VALUED, true) && (!isset($pair[1]) || $pair[1] === '')) {
          throw new HardenException("--{$pair[0]} braucht einen Wert (--{$pair[0]}=…).");
        }
        if (array_key_exists($pair[0], $o->values)) {
          throw new HardenException("--{$pair[0]} ist mehrfach angegeben.");
        }
        $o->values[$pair[0]] = $pair[1] ?? true;
      } elseif ($o->command === '') {
        $o->command = $arg;
      } else {
        throw new HardenException('Unbekanntes Argument: ' . Text::printable($arg));
      }
    }
    if (isset($o->values['password'])) {
      throw new HardenException('Passwörter gehören nicht auf die Kommandozeile (Prozessliste, Shell-Historie). PGPASSWORD oder pgpass-Datei verwenden.');
    }
    return $o;
  }

  public function get(string $key, ?string $default = null): ?string
  {
    $v = $this->values[$key] ?? $default;
    return $v === true ? '1' : $v;
  }

  public function has(string $key): bool
  {
    return array_key_exists($key, $this->values);
  }
}

final class Rule
{
  public function __construct(public readonly array $data) {}

  public function id(): string { return $this->data['id']; }
  public function title(): string { return $this->data['title']; }
  public function category(): string { return $this->data['category'] ?? 'Sonstiges'; }
  public function severity(): string { return $this->data['severity']; }
  public function scope(): string { return $this->data['scope'] ?? 'cluster'; }
  public function automation(): string { return $this->data['automation'] ?? 'manual'; }
  public function command(): string { return $this->data['command'] ?? 'check'; }
  public function isInventory(): bool { return ($this->data['kind'] ?? '') === 'inventory'; }
  public function check(): array { return $this->data['check']; }
  public function fix(): array { return $this->data['fix'] ?? ['type' => 'manual']; }
}

final class Catalog
{
  private const ENUMS = [
    'severity' => ['high', 'medium', 'low', 'info'],
    'automation' => ['auto', 'confirm', 'manual'],
    'scope' => ['cluster', 'database'],
    'requires' => ['superuser', 'settings', 'hba', 'local'],
    'kind' => ['inventory'],
    'command' => ['check', 'client'],
  ];
  private const OPS = ['eq', 'neq', 'in', 'not_in', 'gt', 'gte', 'lt', 'lte'];

  /** @var Rule[] */
  public array $rules = [];
  public array $mappings = [];
  public string $version = '';

  public static function load(string $baseDir): self
  {
    $c = new self();
    $files = self::jsonFiles($baseDir . '/rules');
    if ($files === []) {
      throw new HardenException("Kein Regelkatalog unter $baseDir/rules gefunden.");
    }
    foreach ($files as $file) {
      $data = self::readJson($file);
      if (!isset($data['rules']) || !is_array($data['rules']) || $data['rules'] === []) {
        throw new HardenException("$file enthält keine Regeln.");
      }
      $c->version .= ($c->version === '' ? '' : ', ') . ($data['catalog'] ?? basename($file)) . ' ' . ($data['version'] ?? '?');
      foreach ($data['rules'] as $r) {
        self::validate($r, $file);
        if (isset($c->rules[$r['id']])) {
          throw new HardenException("Doppelte Regel-ID {$r['id']} in $file");
        }
        $c->rules[$r['id']] = new Rule($r);
      }
    }
    foreach (self::jsonFiles($baseDir . '/mappings') as $file) {
      $m = self::readJson($file);
      if (!is_string($m['framework'] ?? null) || !is_array($m['controls'] ?? [])) {
        throw new HardenException(basename($file) . ': framework/controls fehlen oder sind ungültig.');
      }
      foreach ($m['controls'] ?? [] as $control => $def) {
        if (!is_string($def['title'] ?? null)) {
          throw new HardenException("Zuordnung $control in " . basename($file) . ' ohne Titel.');
        }
        if (!is_array($def['rules'] ?? null) || $def['rules'] === []) {
          throw new HardenException("Zuordnung $control in " . basename($file) . ' hat keine Regeln.');
        }
        foreach ($def['rules'] as $ruleId) {
          if (!isset($c->rules[$ruleId])) {
            throw new HardenException("Zuordnung $control in " . basename($file) . " verweist auf unbekannte Regel $ruleId");
          }
        }
      }
      $c->mappings[basename($file, '.json')] = $m;
    }
    return $c;
  }

  private static function validate(array $r, string $file): void
  {
    $id = is_string($r['id'] ?? null) ? $r['id'] : '?';
    foreach (['id', 'title', 'severity', 'check'] as $required) {
      if (!isset($r[$required])) {
        throw new HardenException("Regel $id ohne '$required' in $file");
      }
    }
    foreach (['id', 'title', 'category', 'goal', 'rationale', 'remediation'] as $field) {
      if (isset($r[$field]) && !is_string($r[$field])) {
        throw new HardenException("Regel $id: '$field' muss Text sein ($file)");
      }
    }
    if (!is_array($r['check'])) {
      throw new HardenException("Regel $id: 'check' muss ein Objekt sein ($file)");
    }
    foreach (self::ENUMS as $field => $allowed) {
      if (isset($r[$field]) && !in_array($r[$field], $allowed, true)) {
        throw new HardenException("Regel $id: ungültiger Wert für $field in $file");
      }
    }
    if (isset($r['platform']) && (!is_array($r['platform']) || array_diff($r['platform'], ['linux', 'windows']) !== [])) {
      throw new HardenException("Regel $id: 'platform' muss eine Liste aus linux/windows sein ($file)");
    }
    $check = $r['check'];
    if ($check['type'] === 'setting') {
      if (!isset($check['name'], $check['value']) || !in_array($check['op'] ?? '', self::OPS, true)) {
        throw new HardenException("Regel $id: setting-Prüfung unvollständig in $file");
      }
      if (in_array($check['op'], ['in', 'not_in'], true) !== is_array($check['value'])) {
        throw new HardenException("Regel $id: in/not_in brauchen eine Liste, die übrigen Vergleiche einen Einzelwert");
      }
    } elseif ($check['type'] === 'os') {
      if (!in_array($check['probe'] ?? '', OsProbes::NAMES, true) || ($r['requires'] ?? '') !== 'local') {
        throw new HardenException("Regel $id: unbekannte OS-Prüfung oder 'requires: local' fehlt in $file");
      }
    } elseif ($check['type'] === 'client') {
      if (!in_array($check['probe'] ?? '', ClientProbes::NAMES, true) || ($r['command'] ?? '') !== 'client') {
        throw new HardenException("Regel $id: unbekannte Client-Prüfung oder 'command' fehlt in $file");
      }
    } elseif ($check['type'] === 'weak_passwords') {
      // Built-in check: the candidate list is part of the code, not of the catalog (see class WeakPasswords).
    } elseif ($check['type'] !== 'query' || !is_string($check['sql'] ?? null)) {
      throw new HardenException("Regel $id: unbekannter Prüftyp in $file");
    }
    $fix = $r['fix'] ?? ['type' => 'manual'];
    if (!in_array($fix['type'] ?? '', ['conf', 'sql', 'manual', 'hba'], true) || ($fix['type'] === 'conf' && !is_array($fix['settings'] ?? null))) {
      throw new HardenException("Regel $id: ungültige Korrektur in $file");
    }
    if ($fix['type'] === 'hba') {
      $from = (array) ($fix['from'] ?? []);
      if ($from === [] || !is_string($fix['to'] ?? null) || !in_array($fix['kind'] ?? '', ['method', 'type'], true)
        || array_diff((array) ($fix['requires'] ?? []), ['scram_passwords', 'ssl_on']) !== []) {
        throw new HardenException("Regel $id: hba-Korrektur unvollständig in $file");
      }
    }
    foreach ($fix['settings'] ?? [] as $name => $value) {
      if (!is_string($name) || !preg_match('/^[a-z_][a-z0-9_.]*$/', $name) || !is_scalar($value)) {
        throw new HardenException("Regel $id: ungültiger Parameter in der Korrektur ($file)");
      }
    }
  }

  /** scandir instead of glob: a tool path containing [ or ] must not make the catalog disappear. */
  private static function jsonFiles(string $dir): array
  {
    $out = [];
    foreach (is_dir($dir) ? (scandir($dir) ?: []) : [] as $name) {
      if (str_ends_with($name, '.json')) {
        $out[] = $dir . '/' . $name;
      }
    }
    return $out;
  }

  private static function readJson(string $file): array
  {
    $data = json_decode((string) file_get_contents($file), true);
    if (!is_array($data)) {
      throw new HardenException("Ungültiges JSON in $file: " . json_last_error_msg());
    }
    return $data;
  }
}

final class Connector
{
  private const SSLMODES = ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'];
  private array $pool = [];
  private array $poolRw = [];
  private array $base = [];

  public function __construct(Options $opt)
  {
    $host = $opt->get('host');
    if ($host !== null) {
      if (Text::hasControl($host) || str_contains($host, ';')) {
        throw new HardenException('Ungültiger Hostname.');
      }
      $this->base['host'] = $host;
    }
    $port = $opt->get('port');
    if ($port !== null) {
      if (!ctype_digit($port)) {
        throw new HardenException('--port muss eine Zahl sein.');
      }
      $this->base['port'] = $port;
    }
    $sslmode = $opt->get('sslmode');
    // Effective target includes PGHOST and host lists ("a,b"); any remote entry means TLS is mandatory.
    $effective = $host ?? (getenv('PGHOST') ?: null);
    // A target that libpq resolves from PGHOSTADDR or a service file is not visible here: treat it as remote.
    $unknownTarget = getenv('PGHOSTADDR') !== false || getenv('PGSERVICE') !== false;
    $this->remote = $unknownTarget || ($effective !== null && array_filter(explode(',', $effective), fn($h) => !self::isLocal(trim($h))) !== []);
    if ($sslmode === null && getenv('PGSSLMODE') === false && $this->remote) {
      $sslmode = 'require';
    }
    if ($sslmode !== null) {
      if (!in_array($sslmode, self::SSLMODES, true)) {
        throw new HardenException('--sslmode muss einer von ' . implode(', ', self::SSLMODES) . ' sein.');
      }
      $this->base['sslmode'] = $sslmode;
    }
    $this->sslmode = $sslmode ?? (getenv('PGSSLMODE') ?: null);
    $this->base['application_name'] = 'pg-harden';
    $this->base['client_encoding'] = 'UTF8';
    $this->user = $opt->get('user');
    $this->entry = $opt->get('dbname', 'postgres');
  }

  private ?string $user;
  public readonly string $entry;
  public bool $remote = false;
  public ?string $sslmode = null;

  private static function isLocal(string $host): bool
  {
    return in_array($host, ['localhost', '::1'], true) || preg_match('/^127(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/', $host) === 1 || str_starts_with($host, '/');
  }

  /** The channel is trustworthy if it stays on this machine or the server certificate is verified. */
  public function trusted(): bool
  {
    // verify-ca does not check the host name: a certificate from the same CA for another server would pass.
    return !$this->remote || $this->sslmode === 'verify-full';
  }

  /** Writing commands and the password check send secrets or change the server: no unverified remote channel. */
  public function requireTrusted(string $what): void
  {
    if (!$this->trusted()) {
      throw new HardenException("$what über eine entfernte Verbindung braucht --sslmode=verify-full: ohne Prüfung von Zertifikat und Rechnername kann ein Dritter die Verbindung übernehmen.");
    }
  }

  /**
   * Database names come from the server and are untrusted. Values are libpq-quoted; names that
   * PDO would still mangle (';' becomes a space) or that carry control characters are refused,
   * so a crafted name like "x host=evil" can never redirect the superuser connection.
   */
  public static function connectable(string $dbname): bool
  {
    return !Text::hasControl($dbname) && !str_contains($dbname, ';');
  }

  public function connect(?string $dbname = null): PDO
  {
    $dbname ??= $this->entry;
    return $this->pool[$dbname] ??= $this->open($dbname, false);
  }

  /** Write-capable connection, only for `apply`/`rollback`; everything else stays read-only. */
  public function connectWritable(?string $dbname = null): PDO
  {
    $dbname ??= $this->entry;
    return $this->poolRw[$dbname] ??= $this->open($dbname, true);
  }

  /** A brand-new read-only connection that bypasses the pool — proves that NEW logins still work after a reload. */
  public function fresh(?string $dbname = null): PDO
  {
    return $this->open($dbname ?? $this->entry, false);
  }

  private function open(string $dbname, bool $writable): PDO
  {
    if (!self::connectable($dbname)) {
      throw new HardenException('Datenbankname mit Steuerzeichen oder Semikolon — Verbindung verweigert: ' . Text::printable($dbname));
    }
    $parts = [];
    foreach ($this->base + ['dbname' => $dbname] as $key => $value) {
      $parts[] = $key . "='" . strtr((string) $value, ['\\' => '\\\\', "'" => "\\'"]) . "'";
    }
    try {
      $pdo = new PDO('pgsql:' . implode(' ', $parts), $this->user, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
      ]);
      // Defence in depth; every check additionally runs in its own read-only transaction.
      $pdo->exec($writable ? <<<'SQL'
        SET standard_conforming_strings = on;
        SET statement_timeout = '30s';
        SET lock_timeout = '5s';
        SET search_path = pg_catalog, pg_temp;
        SQL : <<<'SQL'
        SET default_transaction_read_only = on;
        SET standard_conforming_strings = on;
        SET statement_timeout = '15s';
        SET lock_timeout = '2s';
        SET search_path = pg_catalog, pg_temp;
        SQL);
    } catch (PDOException $e) {
      throw new HardenException("Verbindung zu Datenbank '" . Text::printable($dbname) . "' fehlgeschlagen: " . strtok($e->getMessage(), "\n"), 0, $e);
    }
    return $pdo;
  }

  /** Runs one statement read-only and always rolls back; a failing ROLLBACK never hides the original error. */
  public static function readOnly(PDO $pdo, string $sql, array $params = []): array
  {
    $pdo->exec('BEGIN TRANSACTION READ ONLY');
    $error = null;
    try {
      $stmt = $pdo->prepare($sql);
      $stmt->execute($params);
      $rows = $stmt->fetchAll();
    } catch (Throwable $e) {
      $error = $e;
    }
    try {
      $pdo->exec('ROLLBACK');
    } catch (Throwable $rollbackError) {
      throw new HardenException('Verbindung nach Fehler unbrauchbar: ' . strtok(($error ?? $rollbackError)->getMessage(), "\n"), 0, $error ?? $rollbackError);
    }
    if ($error !== null) {
      throw $error;
    }
    return $rows;
  }
}

final class ServerContext
{
  public int $versionNum = 0;
  public string $version = '';
  public string $user = '';
  public string $server = '';
  public bool $ssl = false;
  public bool $superuser = false;
  public bool $readAllSettings = false;
  public bool $readHba = false;
  public array $databases = [];
  /** Database name => reason it was not checked. */
  public array $refusedDatabases = [];
  /** Set when the server runs on this machine (proven via postmaster.pid); OS rules need it. */
  public ?LocalServer $local = null;
  public string $localNote = '';
  /** "Not local" is a plain skip; "could not find out" leaves the check incomplete. */
  public bool $localIncomplete = false;

  public static function load(Connector $connector, Options $opt): self
  {
    $pdo = $connector->connect();
    $c = new self();
    $row = Connector::readOnly($pdo, <<<'SQL'
      SELECT current_setting('server_version_num')::int AS num
           , current_setting('server_version') AS version
           , current_user AS usr
           , current_setting('is_superuser') = 'on' AS su
           , pg_has_role(current_user, 'pg_read_all_settings', 'USAGE') AS ras
           , (has_function_privilege('pg_catalog.pg_hba_file_rules()', 'EXECUTE') AND has_table_privilege('pg_catalog.pg_hba_file_rules', 'SELECT')) AS hba
           , coalesce(host(inet_server_addr()) || ':' || inet_server_port(), 'Unix-Socket') AS server
           , coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) AS ssl
      SQL)[0];
    $c->versionNum = (int) $row['num'];
    $c->version = $row['version'];
    $c->user = $row['usr'];
    $c->server = $row['server'];
    $c->ssl = (bool) $row['ssl'];
    $c->superuser = (bool) $row['su'];
    $c->readAllSettings = $c->superuser || (bool) $row['ras'];
    $c->readHba = $c->superuser || (bool) $row['hba'];
    // template1 is included on purpose: new databases inherit its schema privileges.
    // Only template0 is skipped silently; every other database that is not checked is reported.
    try {
      $rows = Connector::readOnly($pdo, <<<'SQL'
        SELECT datname
             , datallowconn
          FROM pg_database
         WHERE datname <> 'template0'
         ORDER BY datname
        SQL);
    } catch (PDOException $e) {
      if ($e->getCode() !== '42501') {
        throw $e;
      }
      // db.catalog_visibility revokes SELECT on pg_database from PUBLIC: without a grant the database list is unreadable.
      throw new HardenException('Der Rolle fehlt SELECT auf pg_database (Katalog-Sichtbarkeit eingeschränkt, Regel db.catalog_visibility). '
        . 'Als Administrator in jeder Datenbank vergeben: GRANT SELECT ON TABLE pg_catalog.pg_database, pg_catalog.pg_roles TO <rolle>;', 0, $e);
    }
    $all = array_column($rows, 'datname');
    $wanted = null;
    $only = $opt->get('databases');
    if ($only !== null) {
      $wanted = array_map('trim', explode(',', $only));
      $unknown = array_diff($wanted, $all);
      if ($unknown !== []) {
        throw new HardenException('--databases nennt unbekannte Datenbanken: ' . Text::printable(implode(', ', $unknown)));
      }
    }
    foreach ($rows as $r) {
      $db = $r['datname'];
      $reason = match (true) {
        $wanted !== null && !in_array($db, $wanted, true) => 'nicht ausgewählt (--databases)',
        !$r['datallowconn'] => 'Verbindungen nicht erlaubt (datallowconn = false)',
        !Connector::connectable($db) => 'ungewöhnlicher Name (Steuerzeichen oder Semikolon)',
        default => null,
      };
      if ($reason === null) {
        $c->databases[] = $db;
      } else {
        $c->refusedDatabases[$db] = $reason;
      }
    }
    if ($c->readAllSettings) {
      [$c->local, $c->localNote, $c->localIncomplete] = LocalServer::detect($pdo);
    } else {
      $c->localNote = 'braucht pg_read_all_settings';
      $c->localIncomplete = true;
    }
    return $c;
  }
}

/**
 * Weak-password check without a single login attempt: the stored verifiers in pg_authid are recomputed for a
 * short, fixed list of obvious candidates. SCRAM-SHA-256 (PBKDF2-HMAC-SHA256 → ClientKey → StoredKey) and the
 * legacy md5 format are supported. The candidate list is part of the code, plus an optional, strictly bounded operator list (ExtraCandidates): no dictionaries,
 * no brute force. Only the fact "this role uses a listed value" leaves this class — never the candidate, never
 * the hash, and not even which candidate matched.
 * (An empty password cannot be stored by PostgreSQL — it clears the password — so "empty" needs no candidate.)
 */
final class WeakPasswords
{
  private const FIXED = ['postgres', 'password', 'passwort', 'admin', 'changeme', 'secret', 'geheim', 'welcome', 'qwerty', '123456', '12345678', 'root', 'test'];
  private const SUFFIXES = ['1', '123', '!'];
  private const FIRST_YEAR = 2010;
  /** Beyond this the recomputation would cost noticeable CPU time on the machine running the tool: report as not checked. */
  private const MAX_ITERATIONS = 100000;
  public const BUDGET_SECONDS = 60;
  /** @var string[] operator-supplied terms (validated by ExtraCandidates), tried exactly as written */
  private static array $extra = [];

  public static function useExtra(array $list): void
  {
    // Terms that the built-in list contains anyway do not count (the report names the effective number).
    self::$extra = array_values(array_diff($list, self::FIXED));
  }

  public static function extraCount(): int
  {
    return count(self::$extra);
  }
  private const SCRAM = '/^SCRAM-SHA-256\$(\d{1,9}):([A-Za-z0-9+\/]+={0,2})\$([A-Za-z0-9+\/]+={0,2}):([A-Za-z0-9+\/]+={0,2})$/';

  /** @return string[] */
  public static function candidates(string $role, ?int $year = null): array
  {
    $year ??= (int) date('Y');
    $list = self::FIXED;
    foreach ([$role, ucfirst($role)] as $base) {
      $list[] = $base;
      foreach (self::SUFFIXES as $suffix) {
        $list[] = $base . $suffix;
      }
      for ($y = self::FIRST_YEAR; $y <= $year + 1; $y++) {
        $list[] = $base . $y;
      }
    }
    $out = [];
    foreach (array_unique($list) as $candidate) {
      // PostgreSQL applies SASLprep to non-ASCII passwords; the tool does not emulate it, so such candidates are skipped.
      if ($candidate !== '' && !str_contains($candidate, "\0") && preg_match('/^[\x20-\x7E]+$/', $candidate) === 1) {
        $out[] = $candidate;
      }
    }
    // The operator's terms are never expanded (no years, suffixes or substitutions).
    foreach (self::$extra as $candidate) {
      if (!in_array($candidate, $out, true)) {
        $out[] = $candidate;
      }
    }
    return $out;
  }

  public static function matchesMd5(string $stored, string $role, string $password): bool
  {
    return str_starts_with($stored, 'md5') && hash_equals($stored, 'md5' . md5($password . $role));
  }

  /** @return ?bool null = format not supported or parameters out of range (not checked) */
  public static function matchesScram(string $stored, string $password): ?bool
  {
    if (preg_match(self::SCRAM, $stored, $m) !== 1) {
      return null;
    }
    $iterations = (int) $m[1];
    $salt = base64_decode($m[2], true);
    $storedKey = base64_decode($m[3], true);
    if ($iterations < 1 || $iterations > self::MAX_ITERATIONS || $salt === false || $storedKey === false || strlen($storedKey) !== 32) {
      return null;
    }
    $salted = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
    $clientKey = hash_hmac('sha256', 'Client Key', $salted, true);
    return hash_equals($storedKey, hash('sha256', $clientKey, true));
  }

  /** @return array{0: array[], 1: int, 2: int} findings, roles that could not be checked, of those: roles left out by the time budget */
  public static function findings(PDO $pdo): array
  {
    $rows = Connector::readOnly($pdo, <<<'SQL'
      SELECT rolname
           , rolpassword
        FROM pg_authid
       WHERE rolcanlogin
         AND rolpassword IS NOT NULL
       ORDER BY rolname
      SQL);
    $findings = [];
    $unchecked = 0;
    $overBudget = 0;
    // The work is bounded: a server with very many roles or high iteration counts must not keep this machine busy.
    $deadline = microtime(true) + self::BUDGET_SECONDS;
    foreach ($rows as $row) {
      if (microtime(true) > $deadline) {
        $unchecked++;
        $overBudget++;
        continue;
      }
      $role = (string) $row['rolname'];
      $stored = (string) $row['rolpassword'];
      $hit = false;
      $checked = true;
      if (str_starts_with($stored, 'md5')) {
        foreach (self::candidates($role) as $candidate) {
          if (microtime(true) > $deadline) {
            $checked = false;
            $overBudget++;
            break;
          }
          if (self::matchesMd5($stored, $role, $candidate)) {
            $hit = true;
            break;
          }
        }
      } else {
        foreach (self::candidates($role) as $candidate) {
          if (microtime(true) > $deadline) {
            $checked = false;
            $overBudget++;
            break;
          }
          $match = self::matchesScram($stored, $candidate);
          if ($match === null) {
            $checked = false;
            break;
          }
          if ($match) {
            $hit = true;
            break;
          }
        }
      }
      if ($hit) {
        $findings[] = [
          'database' => null,
          'object' => $role,
          'detail' => 'Passwort stammt aus der Prüfliste (wird nicht ausgegeben)',
          'fix_sql' => null,
          'rollback_sql' => null,
        ];
      } elseif (!$checked) {
        $unchecked++;
      }
    }
    return [$findings, $unchecked, $overBudget];
  }
}

/**
 * The operator's own list for the password check: a small file of business-specific terms (company, products, place).
 * Deliberately limited so that it stays a check list and cannot become a dictionary: at most 100 entries of at most
 * 64 printable ASCII characters, read from a file only the operator can access. Errors never quote the content.
 */
final class ExtraCandidates
{
  public const MAX_ENTRIES = 100;
  public const MAX_LENGTH = 64;

  /** @return string[] */
  public static function load(string $path): array
  {
    if (Text::hasControl($path) || preg_match('~^[a-z][a-z0-9+.-]+://~i', $path) === 1) {
      throw new HardenException('--extra-candidates: ungültiger Dateiname (nur lokale Dateien).');
    }
    $max = self::MAX_ENTRIES * (self::MAX_LENGTH + 2) + 1024;
    // One handle for the checks and the read: a file swapped in between is not what we inspected. Without blocking ("n"): a FIFO
    // would otherwise hang in open() before fstat can refuse it (see Fs::read).
    $fh = Fs::attempt(fn() => fopen($path, 'rbn'));
    if (!is_resource($fh)) {
      throw new HardenException('--extra-candidates: Datei nicht lesbar.');
    }
    try {
      $st = fstat($fh);
      if ($st === false || ($st['mode'] & 0170000) !== 0100000) {
        throw new HardenException('--extra-candidates: keine reguläre Datei.');
      }
      if ($st['size'] > $max) {
        throw new HardenException('--extra-candidates: die Datei ist zu groß (höchstens ' . self::MAX_ENTRIES . ' Einträge).');
      }
      if (Platform::windows()) {
        self::checkWindowsAcl($path);
        $again = fstat($fh);
        if ($again === false || $again['size'] !== $st['size'] || $again['mtime'] !== $st['mtime']) {
          throw new HardenException('--extra-candidates: die Datei wurde während der Prüfung verändert.');
        }
      } else {
        if (!function_exists('posix_geteuid')) {
          throw new HardenException('--extra-candidates braucht die PHP-Erweiterung posix (Besitzerprüfung).');
        }
        $link = Fs::attempt(fn() => lstat($path));
        if ($link === null || $link['ino'] !== $st['ino'] || $link['dev'] !== $st['dev']) {
          throw new HardenException('--extra-candidates: der Pfad ist ein symbolischer Link oder wurde während der Prüfung ersetzt.');
        }
        if ($st['uid'] !== posix_geteuid() || ($st['mode'] & 0077) !== 0) {
          throw new HardenException('--extra-candidates: die Datei muss dem ausführenden Benutzer gehören und darf für andere nicht zugänglich sein (chmod 600).');
        }
      }
      Fs::attempt(fn() => stream_set_blocking($fh, true));
      $content = stream_get_contents($fh, $max + 1);
    } finally {
      fclose($fh);
    }
    if ($content === false || strlen($content) > $max) {
      throw new HardenException('--extra-candidates: Datei nicht vollständig lesbar oder zu groß.');
    }
    $content = str_starts_with($content, "\xEF\xBB\xBF") ? substr($content, 3) : $content;
    $list = [];
    foreach (preg_split('/\r\n|\n|\r/', $content) as $i => $line) {
      if ($line === '') {
        continue;
      }
      $n = $i + 1;
      if (strlen($line) > self::MAX_LENGTH) {
        throw new HardenException("--extra-candidates: Zeile $n ist länger als " . self::MAX_LENGTH . ' Zeichen.');
      }
      if (preg_match('/^[\x20-\x7E]+$/', $line) !== 1) {
        throw new HardenException("--extra-candidates: Zeile $n enthält nicht druckbare oder Nicht-ASCII-Zeichen (Tabulator, Umlaute, UTF-16 …; werden nicht unterstützt).");
      }
      if ($line !== trim($line)) {
        throw new HardenException("--extra-candidates: Zeile $n beginnt oder endet mit einem Leerzeichen — meist ein Versehen, deshalb abgewiesen.");
      }
      $list[$line] = true;
    }
    if ($list === []) {
      throw new HardenException('--extra-candidates: die Datei enthält keine Einträge.');
    }
    if (count($list) > self::MAX_ENTRIES) {
      throw new HardenException('--extra-candidates: mehr als ' . self::MAX_ENTRIES . ' Einträge — die Liste ist als kleine Prüfliste gedacht, nicht als Wörterbuch.');
    }
    return array_map('strval', array_keys($list));
  }

  /** Windows: owner is this account (or Administrators) and only this account, SYSTEM and Administrators have access. */
  private static function checkWindowsAcl(string $path): void
  {
    $acl = WindowsFacts::strictAcl($path);
    $me = Platform::currentSid();
    $allowed = array_filter([$me, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-0']);
    if ($acl === null || $me === null || !in_array($acl['owner'], [$me, 'S-1-5-32-544'], true)
      || array_filter($acl['sids'], fn($sid) => !in_array($sid, $allowed, true)) !== []) {
      throw new HardenException('--extra-candidates: Besitzer oder Zugriffsliste der Datei sind nicht eingeschränkt genug (nur dieses Konto, SYSTEM und Administratoren; unbekannte Einträge zählen nicht) — oder die ACL ist nicht lesbar.');
    }
  }
}

final class Checker
{
  public function __construct(
    private readonly Connector $connector,
    private readonly ServerContext $ctx,
    private readonly Catalog $catalog,
  ) {}

  public function run(): array
  {
    $rules = array_filter($this->catalog->rules, fn(Rule $r) => $r->command() === 'check');
    return array_map(fn(Rule $r) => $this->evaluate($r), array_values($rules));
  }

  public static function blank(Rule $rule): array
  {
    return [
      'id' => $rule->id(),
      'title' => $rule->title(),
      'category' => $rule->category(),
      'severity' => $rule->severity(),
      'goal' => $rule->data['goal'] ?? '',
      'automation' => $rule->automation(),
      'scope' => $rule->scope(),
      'status' => 'pass',
      'incomplete' => false,
      'value' => '',
      'notes' => [],
      'findings' => [],
      'checked_databases' => [],
    ];
  }

  /**
   * Status rules: findings always win (fail), even if some databases could not be checked;
   * anything not checked sets "incomplete" so neither the exit code nor verify can treat it as clean.
   */
  private function evaluate(Rule $rule): array
  {
    $result = self::blank($rule);
    [$skip, $incomplete] = $this->skipReason($rule);
    if ($skip !== null) {
      return ['status' => 'skip', 'incomplete' => $incomplete, 'notes' => [$skip]] + $result;
    }
    if ($rule->scope() === 'database') {
      $targets = $this->ctx->databases;
      foreach ($this->ctx->refusedDatabases as $db => $reason) {
        $result['incomplete'] = true;
        $result['notes'][] = 'nicht geprüft: ' . Text::printable((string) $db) . " — $reason";
      }
      if ($targets === []) {
        return ['status' => 'skip', 'incomplete' => true, 'notes' => array_merge($result['notes'], ['keine Datenbank geprüft'])] + $result;
      }
    } else {
      $targets = [null];
    }
    $errors = 0;
    foreach ($targets as $db) {
      try {
        $pdo = $this->connector->connect($db);
        $found = $this->findings($pdo, $rule, $db, $result);
        $result['findings'] = array_merge($result['findings'], $found);
        if ($db !== null) {
          $result['checked_databases'][] = $db;
        }
      } catch (HardenException $e) {
        $errors++;
        $result['notes'][] = $e->getMessage();
      } catch (ErrorException $e) {
        $errors++;
        $result['notes'][] = strtok($e->getMessage(), "\n") ?: 'PHP-Fehler';
      } catch (PDOException $e) {
        $errors++;
        $prefix = $db !== null ? '[' . Text::printable($db) . '] ' : '';
        $reason = $e->getCode() === '42501' ? 'keine Berechtigung: ' : '';
        $result['notes'][] = $prefix . $reason . strtok($e->getMessage(), "\n");
      }
    }
    if ($result['status'] === 'skip') {
      return $result;
    }
    if ($errors > 0) {
      $result['incomplete'] = true;
    }
    $result['status'] = match (true) {
      $rule->isInventory() => $errors === count($targets) ? 'error' : 'info',
      $result['findings'] !== [] => 'fail',
      $errors === count($targets) => 'error',
      default => 'pass',
    };
    return $result;
  }

  /** @return array{0: ?string, 1: bool} reason, and whether the skip leaves the check incomplete */
  private function skipReason(Rule $rule): array
  {
    $d = $rule->data;
    if (isset($d['min_version']) && $this->ctx->versionNum < $d['min_version']) {
      return ['erst ab Version ' . intdiv((int) $d['min_version'], 10000), false];
    }
    if (isset($d['max_version']) && $this->ctx->versionNum > $d['max_version']) {
      return ['nur bis Version ' . intdiv((int) $d['max_version'], 10000), false];
    }
    if (isset($d['platform']) && !in_array(Platform::windows() ? 'windows' : 'linux', (array) $d['platform'], true)) {
      return ['nur ' . implode('/', (array) $d['platform']), false];
    }
    $requires = $d['requires'] ?? null;
    if ($requires === 'local' && $this->ctx->local === null) {
      return [$this->ctx->localNote, $this->ctx->localIncomplete];
    }
    if ($requires === 'superuser' && !$this->ctx->superuser) {
      return ['braucht Superuser', true];
    }
    if ($requires === 'settings' && !$this->ctx->readAllSettings) {
      return ['braucht pg_read_all_settings', true];
    }
    if ($requires === 'hba' && !$this->ctx->readHba) {
      return ['braucht EXECUTE auf pg_hba_file_rules() und SELECT auf die View pg_hba_file_rules', true];
    }
    return [null, false];
  }

  private function findings(PDO $pdo, Rule $rule, ?string $db, array &$result): array
  {
    $check = $rule->check();
    if ($check['type'] === 'setting') {
      return $this->settingFindings($pdo, $check, $result);
    }
    if ($check['type'] === 'os') {
      $probe = OsProbes::run($check['probe'], $this->ctx->local);
      if ($probe['unchecked'] !== []) {
        $result['incomplete'] = true;
        foreach ($probe['unchecked'] as $u) {
          $result['notes'][] = 'nicht geprüft: ' . $u;
        }
      }
      array_push($result['notes'], ...$probe['notes']);
      return $probe['findings'];
    }
    if ($check['type'] === 'weak_passwords') {
      if (!$this->connector->trusted()) {
        throw new HardenException('nicht geprüft: die Verifier würden über eine entfernte Verbindung ohne Zertifikatsprüfung gelesen — --sslmode=verify-full');
      }
      $result['notes'][] = 'Geprüft wurde nur eine kurze Liste naheliegender Werte'
        . (WeakPasswords::extraCount() > 0 ? ' und ' . WeakPasswords::extraCount() . (WeakPasswords::extraCount() === 1 ? ' vom Betreiber bereitgestellter Begriff' : ' vom Betreiber bereitgestellte Begriffe') : '')
        . ' — das sagt nichts über die Stärke der übrigen Passwörter.';
      [$found, $unchecked, $overBudget] = WeakPasswords::findings($pdo);
      if ($unchecked > 0) {
        $result['incomplete'] = true;
        $result['notes'][] = "$unchecked Rolle(n) nicht vollständig geprüft"
          . ($overBudget > 0 ? ' (Zeitbudget von ' . WeakPasswords::BUDGET_SECONDS . ' s erschöpft; die Reihenfolge ist alphabetisch)' : ' (Passwortformat unbekannt oder Iterationszahl über dem Prüflimit)');
      }
      return $found;
    }
    $out = [];
    foreach (Connector::readOnly($pdo, $check['sql']) as $row) {
      $out[] = [
        'database' => $db,
        'object' => (string) ($row['object'] ?? ''),
        'detail' => (string) ($row['detail'] ?? ''),
        'fix_sql' => $row['fix_sql'] ?? null,
        'rollback_sql' => $row['rollback_sql'] ?? null,
      ] + (isset($row['hba_line']) ? ['hba_line' => (int) $row['hba_line'], 'hba_type' => (string) ($row['hba_type'] ?? '')] : []);
    }
    return $out;
  }

  private function settingFindings(PDO $pdo, array $check, array &$result): array
  {
    $rows = Connector::readOnly($pdo, 'SELECT setting, unit FROM pg_settings WHERE name = :name', ['name' => $check['name']]);
    if ($rows === []) {
      // pg_settings hides some parameters from roles without pg_read_all_settings —
      // "invisible" must never be mistaken for "does not exist in this version".
      if (!$this->ctx->readAllSettings) {
        throw new HardenException("Parameter {$check['name']} nicht sichtbar (pg_read_all_settings nötig)");
      }
      $result['status'] = 'skip';
      $result['notes'][] = "Parameter {$check['name']} gibt es in dieser Version nicht";
      return [];
    }
    $actual = (string) $rows[0]['setting'];
    $result['value'] = "{$check['name']} = $actual" . ($rows[0]['unit'] ? " ({$rows[0]['unit']})" : '');
    if ($this->matches($actual, $check['op'], $check['value'])) {
      return [];
    }
    return [[
      'database' => null,
      'object' => $check['name'],
      'detail' => "ist '$actual', erwartet " . $this->describe($check['op'], $check['value']),
      'fix_sql' => null,
      'rollback_sql' => null,
    ]];
  }

  private function matches(string $actual, string $op, mixed $expected): bool
  {
    $a = strtolower($actual);
    return match ($op) {
      'eq' => $a === strtolower((string) $expected),
      'neq' => $a !== strtolower((string) $expected),
      'in' => in_array($a, array_map('strtolower', $expected), true),
      'not_in' => !in_array($a, array_map('strtolower', $expected), true),
      'gt' => is_numeric($actual) && (float) $actual > (float) $expected,
      'gte' => is_numeric($actual) && (float) $actual >= (float) $expected,
      'lt' => is_numeric($actual) && (float) $actual < (float) $expected,
      'lte' => is_numeric($actual) && (float) $actual <= (float) $expected,
    };
  }

  private function describe(string $op, mixed $value): string
  {
    $v = is_array($value) ? implode(', ', $value) : (string) $value;
    return match ($op) {
      'eq' => "'$v'",
      'neq' => "nicht '$v'",
      'in' => "eines von: $v",
      'not_in' => "keines von: $v",
      'gt' => "größer als $v",
      'gte' => "mindestens $v",
      'lt' => "kleiner als $v",
      'lte' => "höchstens $v",
    };
  }
}

final class ClientChecker
{
  public static function run(Catalog $catalog, ClientContext $ctx): array
  {
    $out = [];
    foreach ($catalog->rules as $rule) {
      if ($rule->command() !== 'client') {
        continue;
      }
      $result = Checker::blank($rule);
      $platform = $rule->data['platform'] ?? null;
      if ($platform !== null && !in_array(Platform::windows() ? 'windows' : 'linux', $platform, true)) {
        $out[] = ['status' => 'skip', 'notes' => ['nur ' . implode('/', $platform)]] + $result;
        continue;
      }
      try {
        $probe = ClientProbes::run($rule->check()['probe'], $ctx);
      } catch (HardenException | ErrorException $e) {
        $out[] = ['status' => 'error', 'incomplete' => true, 'notes' => [strtok($e->getMessage(), "\n") ?: 'PHP-Fehler']] + $result;
        continue;
      }
      $result['findings'] = $probe['findings'];
      foreach ($probe['unchecked'] as $u) {
        $result['incomplete'] = true;
        $result['notes'][] = 'nicht geprüft: ' . $u;
      }
      array_push($result['notes'], ...$probe['notes']);
      $result['status'] = match (true) {
        $rule->isInventory() => 'info',
        $result['findings'] !== [] => 'fail',
        default => 'pass',
      };
      $out[] = $result;
    }
    return $out;
  }
}

final class Report
{
  public const SEVERITY_ORDER = ['high' => 0, 'medium' => 1, 'low' => 2, 'info' => 3];
  public const SEVERITY_LABEL = ['high' => 'hoch', 'medium' => 'mittel', 'low' => 'niedrig', 'info' => 'Info'];
  public const STATUS_LABEL = ['pass' => 'OK', 'fail' => 'BEFUND', 'info' => 'SICHTEN', 'skip' => 'ÜBERSPRUNGEN', 'error' => 'FEHLER'];

  /** @return array{0: array, 1: bool} status counts and whether the intended-use notice belongs into the header */
  private static function summarize(Catalog $catalog, array $results): array
  {
    $counts = ['pass' => 0, 'fail' => 0, 'info' => 0, 'skip' => 0, 'error' => 0, 'incomplete' => 0];
    $legal = false;
    foreach ($results as $r) {
      $counts[$r['status']]++;
      if ($r['incomplete']) {
        $counts['incomplete']++;
      }
      // Reports that contain password or client results carry the intended-use notice in their header.
      $legal = $legal || ($r['status'] !== 'skip' && ($catalog->rules[$r['id']]->data['legal_notice'] ?? false) === true);
    }
    return [$counts, $legal];
  }

  public static function build(ServerContext $ctx, Catalog $catalog, array $results, Options $opt, Connector $connector): array
  {
    [$counts, $legal] = self::summarize($catalog, $results);
    return [
      'meta' => [
        'tool' => 'pg-harden ' . PG_HARDEN_VERSION,
        'mode' => 'server',
        'created_at' => date(DATE_ATOM),
        'host' => $opt->get('host', '(libpq-Standard)') . ($opt->has('port') ? ':' . $opt->get('port') : ''),
        'server' => $ctx->server,
        'ssl' => $ctx->ssl,
        'certificate_verified' => in_array($connector->sslmode, ['verify-ca', 'verify-full'], true),
        'remote' => $connector->remote,
        'server_version' => $ctx->version,
        'user' => $ctx->user,
        'superuser' => $ctx->superuser,
        'local_server' => $ctx->local !== null,
        'local_note' => $ctx->localNote,
        'databases' => $ctx->databases,
        'refused_databases' => $ctx->refusedDatabases,
        'catalog' => $catalog->version,
        'counts' => $counts,
        'mapping_disclaimer' => MAPPING_DISCLAIMER,
        'notice' => RESPONSIBILITY_NOTICE,
        'legal_notice' => $legal ? LEGAL_NOTICE : null,
      ],
      'results' => $results,
      'mappings' => self::mappingStatus($catalog, $results),
    ];
  }

  public static function buildClient(ClientContext $ctx, Catalog $catalog, array $results): array
  {
    [$counts] = self::summarize($catalog, $results);
    return [
      'meta' => [
        'tool' => 'pg-harden ' . PG_HARDEN_VERSION,
        'mode' => 'client',
        'created_at' => date(DATE_ATOM),
        'host' => (string) gethostname(),
        'server' => (string) gethostname(),
        'ssl' => false,
        'certificate_verified' => false,
        'remote' => false,
        'server_version' => '',
        'user' => $ctx->account,
        'superuser' => false,
        'local_server' => false,
        'local_note' => '',
        'databases' => [],
        'refused_databases' => [],
        'catalog' => $catalog->version,
        'counts' => $counts,
        'mapping_disclaimer' => MAPPING_DISCLAIMER,
        'notice' => RESPONSIBILITY_NOTICE,
        'legal_notice' => LEGAL_NOTICE,
      ],
      'results' => $results,
      'mappings' => self::mappingStatus($catalog, $results),
    ];
  }

  private static function mappingStatus(Catalog $catalog, array $results): array
  {
    $byId = [];
    foreach ($results as $r) {
      $byId[$r['id']] = $r;
    }
    $out = [];
    foreach ($catalog->mappings as $key => $m) {
      $controls = [];
      foreach ($m['controls'] ?? [] as $control => $def) {
        // A report only contains the rules of its command: controls without any evaluated rule stay out of it.
        $mapped = array_values(array_filter(array_map(fn($id) => $byId[$id] ?? null, $def['rules'])));
        if ($mapped === []) {
          continue;
        }
        $applicable = array_filter($mapped, fn($r) => !($r['status'] === 'skip' && !$r['incomplete']));
        $clean = count(array_filter($applicable, fn($r) => $r['status'] === 'pass' && !$r['incomplete']));
        $has = fn(callable $p) => array_filter($applicable, $p) !== [];
        $state = match (true) {
          $applicable === [] => 'nicht anwendbar',
          $has(fn($r) => $r['status'] === 'fail') => 'Befund',
          $has(fn($r) => $r['incomplete'] || in_array($r['status'], ['error', 'skip'], true)) => 'nicht vollständig geprüft',
          $has(fn($r) => $r['status'] === 'info') => 'Sichtung nötig',
          default => 'ohne Befund',
        };
        $controls[] = [
          'control' => (string) $control,
          'title' => $def['title'],
          'state' => $state,
          'rules_clean' => $clean . ' von ' . count($applicable),
          'rules' => array_values(array_filter($def['rules'], fn($id) => isset($byId[$id]))),
        ];
      }
      $out[$key] = ['framework' => $m['framework'], 'verified' => (bool) ($m['verified'] ?? false), 'note' => $m['note'] ?? '', 'controls' => $controls];
    }
    return $out;
  }

  public static function exitCode(array $report): int
  {
    $c = $report['meta']['counts'];
    $cmp = $report['comparison'] ?? null;
    return match (true) {
      $c['fail'] > 0 => 1,
      $c['error'] > 0 || $c['incomplete'] > 0 => 3,
      $cmp !== null && ($cmp['warnings'] !== [] || $cmp['not_comparable'] !== []) => 3,
      default => 0,
    };
  }

  /** Categories keep the order of the catalog; within a category by severity, then id. */
  public static function sorted(array $results): array
  {
    $rank = array_flip(array_values(array_unique(array_column($results, 'category'))));
    usort($results, fn($a, $b) => [$rank[$a['category']], self::SEVERITY_ORDER[$a['severity']], $a['id']]
      <=> [$rank[$b['category']], self::SEVERITY_ORDER[$b['severity']], $b['id']]);
    return $results;
  }

  /** Findings first (most severe first), then errors, rules to review, incomplete, skipped, clean; within that the catalog order. */
  public static function byAttention(array $results): array
  {
    $rank = fn(array $r) => match (true) {
      $r['status'] === 'fail' => 0,
      $r['status'] === 'error' => 1,
      $r['status'] === 'info' => 2,
      $r['status'] === 'pass' && $r['incomplete'] => 3,
      $r['status'] === 'skip' => 4,
      default => 5,
    };
    $sorted = self::sorted($results);
    $pos = array_flip(array_column($sorted, 'id'));
    usort($sorted, fn($a, $b) => [$rank($a), $a['status'] === 'fail' ? self::SEVERITY_ORDER[$a['severity']] : 0, $pos[$a['id']]]
      <=> [$rank($b), $b['status'] === 'fail' ? self::SEVERITY_ORDER[$b['severity']] : 0, $pos[$b['id']]]);
    return $sorted;
  }

  public static function findingLine(array $f): string
  {
    return ($f['database'] !== null ? '[' . Text::printable($f['database']) . '] ' : '')
      . Text::printable($f['object']) . ($f['detail'] !== '' ? ': ' . Text::printable($f['detail']) : '');
  }
}

final class TextRenderer
{
  /** Line width of the terminal report; long titles and findings wrap with a hanging indent. */
  public const WIDTH = 110;
  /** Column of the rule title: two spaces, the rule id padded to 29, one space. */
  private const INDENT = 32;

  public static function render(array $report): string
  {
    $m = $report['meta'];
    $c = $m['counts'];
    $client = ($m['mode'] ?? 'server') === 'client';
    $kind = $client ? 'Client-Prüfung' : (isset($report['comparison']) ? 'Prüfbericht mit Vergleich' : 'Prüfbericht');
    $out = 'pg-harden ' . PG_HARDEN_VERSION . " · $kind · " . self::when($m['created_at'] ?? '') . "\n";
    if ($client) {
      $out .= self::field('Rechner', Text::printable($m['server']) . ' · Konto ' . Text::printable($m['user']));
    } else {
      $out .= self::field('Server', Text::printable($m['server']) . ' · PostgreSQL ' . Text::printable($m['server_version'])
        . ' · Benutzer ' . Text::printable($m['user']) . ($m['superuser'] ? ' (Superuser)' : '') . ' · ' . ($m['ssl'] ? 'TLS' : 'ohne TLS'));
      $out .= self::field('Umfang', 'Datenbanken ' . Text::printable(implode(', ', $m['databases'])) . ' · Betriebssystem-Regeln '
        . ($m['local_server'] ? 'geprüft' : 'nicht geprüft (' . Text::printable($m['local_note']) . ')'));
      foreach ($m['refused_databases'] as $db => $reason) {
        $out .= self::field('Nicht geprüft', Text::printable((string) $db) . " — $reason");
      }
      if ($m['remote'] && !$m['certificate_verified']) {
        $out .= self::field('Achtung', 'Serverzertifikat nicht geprüft — für entfernte Hosts --sslmode=verify-full verwenden');
      }
    }
    $out .= self::field('Katalog', Text::printable((string) $m['catalog']) . ' · '
      . (($m['legal_notice'] ?? null) !== null ? 'Hinweise zu Verwendung und Gewähr am Ende' : 'Hinweis zur Gewähr am Ende'));

    $bySeverity = array_fill_keys(array_keys(Report::SEVERITY_ORDER), []);
    $groups = ['error' => [], 'info' => [], 'incomplete' => [], 'skip' => [], 'pass' => []];
    foreach (Report::sorted($report['results']) as $r) {
      match (true) {
        $r['status'] === 'fail' => $bySeverity[$r['severity']][] = $r,
        $r['status'] === 'pass' && $r['incomplete'] => $groups['incomplete'][] = $r,
        default => $groups[$r['status']][] = $r,
      };
    }
    $severities = [];
    foreach ($bySeverity as $sev => $list) {
      if ($list !== []) {
        $severities[] = count($list) . ' ' . Report::SEVERITY_LABEL[$sev];
      }
    }
    // The same numbers as the sections below: "ohne Befund" counts only fully checked rules.
    $rest = count($groups['pass']) . ' ohne Befund · ' . count($groups['incomplete']) . ' ohne Befund, aber nicht vollständig geprüft · '
      . "{$c['info']} zu sichten · {$c['skip']} übersprungen · {$c['error']} Fehler";
    $out .= "\nZUSAMMENFASSUNG\n";
    $out .= '  ' . mb_str_pad(self::findings($c['fail']), 14) . ($severities === [] ? '' : implode(' · ', $severities)) . "\n";
    $out .= '  ' . self::wrap($rest, 2) . "\n";

    if (isset($report['comparison'])) {
      $out .= Verifier::renderText($report['comparison']);
    }
    foreach ($bySeverity as $sev => $list) {
      if ($list !== []) {
        $out .= "\nBEFUNDE — " . mb_strtoupper(Report::SEVERITY_LABEL[$sev]) . ' (' . count($list) . ")\n" . implode('', array_map(self::item(...), $list));
      }
    }
    $titles = [
      'error' => 'FEHLER BEI DER PRÜFUNG',
      'info' => 'ZU SICHTEN',
      'incomplete' => 'OHNE BEFUND, ABER NICHT VOLLSTÄNDIG GEPRÜFT',
      'skip' => 'ÜBERSPRUNGEN',
      'pass' => 'OHNE BEFUND',
    ];
    foreach ($titles as $key => $title) {
      if ($groups[$key] !== []) {
        $out .= "\n$title (" . count($groups[$key]) . ")\n" . implode('', array_map(self::item(...), $groups[$key]));
      }
    }

    foreach ($report['mappings'] as $map) {
      if ($map['controls'] === []) {
        continue;
      }
      $out .= "\nZUORDNUNG " . mb_strtoupper(Text::printable($map['framework'])) . ($map['verified'] ? '' : ' — Kennungen ungeprüft') . "\n";
      $out .= '  ' . self::wrap(MAPPING_DISCLAIMER, 2) . "\n\n";
      $out .= '  ' . mb_str_pad('Kennung', 9) . mb_str_pad('Ergebnis der Regeln', 28) . mb_str_pad('ohne Befund', 13) . "Thema\n";
      foreach ($map['controls'] as $ctl) {
        $out .= '  ' . mb_str_pad($ctl['control'], 9) . mb_str_pad($ctl['state'], 28) . mb_str_pad($ctl['rules_clean'], 13) . $ctl['title'] . "\n";
      }
    }

    $out .= "\n" . self::wrap('Ergebnis: ' . self::findings($c['fail']) . ($severities === [] ? '' : ' (' . implode(' · ', $severities) . ')') . " · $rest", 2) . "\n";
    return $out . self::notices($m['legal_notice'] ?? null);
  }

  /** One rule: id column, title, then notes (→) and findings (-) aligned under the title. */
  public static function item(array $r): string
  {
    $pad = str_repeat(' ', self::INDENT);
    $title = $r['title'] . ($r['incomplete'] && $r['status'] === 'fail' ? ' — nicht vollständig geprüft' : '');
    $out = '  ' . mb_str_pad($r['id'], self::INDENT - 3) . ' ' . self::wrap($title, self::INDENT) . "\n";
    foreach ($r['notes'] as $note) {
      $out .= $pad . '→ ' . self::wrap(Text::printable($note), self::INDENT + 2) . "\n";
    }
    foreach ($r['findings'] as $f) {
      $out .= $pad . '- ' . self::wrap(Report::findingLine($f), self::INDENT + 2) . "\n";
    }
    return $out;
  }

  /** The closing block: intended-use notice (when the report carries it) and the responsibility notice, set off from the report. */
  public static function notices(?string $legal): string
  {
    $out = "\n" . self::rule('Hinweise');
    if ($legal !== null) {
      $out .= self::wrap('Bestimmungsgemäße Verwendung: ' . $legal, 0) . "\n\n";
    }
    return $out . self::wrap(RESPONSIBILITY_NOTICE, 0) . "\n" . self::rule();
  }

  /** Label column for the header lines. */
  public static function field(string $label, string $value): string
  {
    return mb_str_pad($label, 14) . self::wrap($value, 14) . "\n";
  }

  /**
   * Word wrap with a hanging indent: the first line starts where the caller already is, every further line at $indent.
   * Measured in characters, not bytes (wordwrap() counts bytes, every umlaut would shorten the line); breaks only at spaces,
   * an overlong word stays whole.
   */
  public static function wrap(string $text, int $indent): string
  {
    $width = max(40, self::WIDTH - $indent);
    $lines = [];
    $line = '';
    foreach (explode(' ', $text) as $word) {
      if ($line !== '' && mb_strlen($line) + 1 + mb_strlen($word) > $width) {
        $lines[] = $line;
        $line = $word;
      } else {
        $line = $line === '' ? $word : "$line $word";
      }
    }
    $lines[] = $line;
    return implode("\n" . str_repeat(' ', $indent), $lines);
  }

  /** "1 Befund", "3 Befunde". */
  public static function findings(int $n): string
  {
    return $n . ($n === 1 ? ' Befund' : ' Befunde');
  }

  public static function rule(string $title = ''): string
  {
    $head = $title === '' ? '' : "── $title ";
    return $head . str_repeat('─', max(3, self::WIDTH - mb_strlen($head))) . "\n";
  }

  /** "2026-10-24T20:25:03+00:00" (also with fractions) → "24.10.2026 20:25 (+00:00)"; anything unparsable is shown as it is. */
  public static function when(string $atom): string
  {
    try {
      $d = new DateTimeImmutable($atom);
    } catch (Exception) {
      return Text::printable($atom);
    }
    return $atom === '' ? '' : $d->format('d.m.Y H:i') . ' (' . $d->format('P') . ')';
  }
}

final class HtmlRenderer
{
  public static function render(array $report): string
  {
    $e = fn($s) => htmlspecialchars(Text::printable((string) $s), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $m = $report['meta'];
    $c = $m['counts'];
    $rows = '';
    foreach (Report::byAttention($report['results']) as $r) {
      $items = '';
      foreach ($r['findings'] as $f) {
        $items .= '<li>' . $e(Report::findingLine($f)) . '</li>';
      }
      $notes = '';
      foreach ($r['notes'] as $n) {
        $notes .= '<div class="note">' . $e($n) . '</div>';
      }
      $rows .= '<tr class="s-' . $e($r['status']) . '"><td>' . $e(Report::STATUS_LABEL[$r['status']])
        . ($r['incomplete'] ? '<div class="note">unvollständig</div>' : '') . '</td><td>'
        . $e(Report::SEVERITY_LABEL[$r['severity']]) . '</td><td>' . $e($r['category']) . '</td><td><strong>'
        . $e($r['title']) . '</strong><div class="id">' . $e($r['id']) . '</div>' . $notes
        . ($items !== '' ? "<ul>$items</ul>" : '') . '</td></tr>';
    }
    $maps = '';
    foreach ($report['mappings'] as $map) {
      if ($map['controls'] === []) {
        continue;
      }
      $maps .= '<h2>Zuordnung ' . $e($map['framework']) . '</h2><p class="note">' . $e(MAPPING_DISCLAIMER)
        . ($map['verified'] ? '' : ' ' . $e($map['note'])) . '</p>';
      $maps .= '<table><thead><tr><th>Kennung</th><th>Thema</th><th>Ergebnis der zugeordneten Regeln</th><th>ohne Befund</th><th>Regeln</th></tr></thead><tbody>';
      foreach ($map['controls'] as $ctl) {
        $maps .= '<tr><td>' . $e($ctl['control']) . '</td><td>' . $e($ctl['title']) . '</td><td>' . $e($ctl['state'])
          . '</td><td>' . $e($ctl['rules_clean']) . '</td><td class="id">' . $e(implode(', ', $ctl['rules'])) . '</td></tr>';
      }
      $maps .= '</tbody></table>';
    }
    $cmp = isset($report['comparison']) ? '<h2>Vergleich</h2><pre>' . $e(Verifier::renderText($report['comparison'])) . '</pre>' : '';
    $client = ($m['mode'] ?? 'server') === 'client';
    $title = 'pg-harden — ' . ($client ? 'Client-Prüfung ' : '') . $m['server'];
    $ssl = $m['ssl'] ? 'TLS' : 'ohne TLS';
    $headline = $client
      ? "Konto {$e($m['user'])} · {$e($m['created_at'])} · {$e($m['tool'])} · Katalog {$e($m['catalog'])}"
      : "PostgreSQL {$e($m['server_version'])} · Benutzer {$e($m['user'])} · Verbindung {$ssl} · {$e($m['created_at'])} · {$e($m['tool'])} · Katalog {$e($m['catalog'])}";
    $legal = ($m['legal_notice'] ?? null) !== null
      ? '<p class="note"><strong>Bestimmungsgemäße Verwendung:</strong> ' . $e($m['legal_notice']) . '</p>' : '';
    $noticeRef = $legal !== '' ? 'Hinweise zu Verwendung und Gewähr am Ende.' : 'Hinweis zur Gewähr am Ende.';
    $passClean = count(array_filter($report['results'], fn($r) => $r['status'] === 'pass' && !$r['incomplete']));
    $passIncomplete = count(array_filter($report['results'], fn($r) => $r['status'] === 'pass' && $r['incomplete']));
    return <<<HTML
      <!doctype html>
      <html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
      <title>{$e($title)}</title>
      <style>
        body{font-family:system-ui,sans-serif;margin:24px;color:#1f2937;background:#fff}
        table{border-collapse:collapse;width:100%;margin:12px 0}
        th,td{border-bottom:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top;font-size:14px}
        .id{color:#6b7280;font-family:monospace;font-size:12px}.note{color:#6b7280;font-size:13px}
        tr.s-fail td:first-child{color:#b91c1c;font-weight:600}tr.s-pass td:first-child{color:#15803d}
        tr.s-error td:first-child{color:#b45309;font-weight:600}ul{margin:4px 0 0 18px;padding:0}pre{white-space:pre-wrap}
      </style></head><body>
      <h1>{$e($title)}</h1>
      <p>{$headline}</p>
      <p><strong>{$e(TextRenderer::findings($c['fail']))}</strong> · {$passClean} ohne Befund · {$passIncomplete} ohne Befund, aber nicht vollständig geprüft · {$c['info']} zu sichten · {$c['skip']} übersprungen · {$c['error']} Fehler</p>
      <p class="note">Der Bericht enthält Rollen-, Objekt- und Netznamen. Vertraulich ablegen und vor einer Weitergabe prüfen. {$noticeRef}</p>
      {$cmp}
      <table><thead><tr><th>Status</th><th>Stufe</th><th>Bereich</th><th>Regel</th></tr></thead><tbody>{$rows}</tbody></table>
      {$maps}
      <h2>Hinweise</h2>
      {$legal}
      <p class="note">{$e(RESPONSIBILITY_NOTICE)}</p>
      </body></html>
      HTML;
  }
}

final class Planner
{
  public function __construct(private readonly Connector $connector, private readonly Catalog $catalog) {}

  public function write(array $report, string $dir): array
  {
    Files::prepareDir($dir);
    $failed = array_filter($report['results'], fn($r) => $r['status'] === 'fail');
    $unplannable = [];
    $this->written = [];
    try {
      $this->writeConf($failed, $dir);
      $this->writeSql($failed, $dir, $unplannable);
      $this->writeManual($failed, $unplannable, $report, $dir);
      $this->put($dir . '/report.json', Text::json($report));
    } catch (Throwable $e) {
      // Never leave half a plan behind: a lone harden_*.sql without MANUELL.md could be run by mistake.
      foreach ($this->written as $file) {
        @unlink($file);
      }
      throw $e;
    }
    return $this->written;
  }

  private array $written = [];

  private function put(string $file, string $content): string
  {
    Files::write($file, $content, exclusive: true);
    return $this->written[] = $file;
  }

  private function writeConf(array $failed, string $dir): string
  {
    $settings = [];
    foreach ($failed as $r) {
      $fix = $this->catalog->rules[$r['id']]->fix();
      if ($fix['type'] === 'conf') {
        foreach ($fix['settings'] as $name => $value) {
          $settings[] = [$r, $name, (string) $value];
        }
      }
    }
    $names = array_values(array_unique(array_column($settings, 1)));
    $current = $this->currentSettings($names);
    $overrides = $this->dbRoleOverrides($names);
    $lines = [
      '# pg-harden ' . PG_HARDEN_VERSION . ' — Änderungsplan, erzeugt ' . date('Y-m-d H:i'),
      '# ' . PLAN_WARNING,
      '# ' . RESPONSIBILITY_NOTICE,
      "# Einbinden: am ENDE von postgresql.conf \"include_dir = 'conf.d'\" eintragen und diese Datei nach conf.d/ legen.",
      '# Später gelesene Zeilen und Dateien mit höherer Nummer in conf.d überschreiben diese Datei.',
      '# Zurücknehmen: Datei entfernen und Konfiguration neu laden; Parameter mit Neustart erst nach Neustart.',
      '# Zeilen mit "#BESTÄTIGEN" sind bewusst auskommentiert: Auswirkung prüfen, dann freischalten.',
      '',
    ];
    $restart = [];
    $lastRule = '';
    foreach ($settings as [$r, $name, $value]) {
      if ($r['id'] !== $lastRule) {
        $lines[] = "# {$r['id']}: {$r['title']}";
        $lastRule = $r['id'];
      }
      $shadow = $this->shadowedBy($current[$name] ?? null);
      if ($shadow !== null) {
        $lines[] = "# ACHTUNG: $name $shadow";
      }
      foreach ($overrides[$name] ?? [] as $o) {
        $lines[] = '# ACHTUNG: ' . Text::printable($o);
      }
      $prefix = $r['automation'] === 'auto' ? '' : '#BESTÄTIGEN ';
      $lines[] = $prefix . $name . " = '" . strtr($value, ['\\' => '\\\\', "'" => "''"]) . "'";
      if (($current[$name]['context'] ?? '') === 'postmaster') {
        $restart[] = $name;
      }
    }
    if ($restart !== []) {
      $lines[] = '';
      $lines[] = '# Neustart erforderlich für: ' . implode(', ', array_unique($restart)) . '; alle übrigen: SELECT pg_reload_conf();';
    }
    return $this->put($dir . '/90-pg-harden.conf', implode("\n", $lines) . "\n");
  }

  /** @return array{current: array, overrides: array, shadow: array<string, ?string>} what keeps an include-file value from taking effect */
  public function inspect(array $names): array
  {
    $names = array_values(array_unique($names));
    $current = $this->currentSettings($names);
    $shadow = [];
    foreach ($names as $name) {
      $shadow[$name] = $this->shadowedBy($current[$name] ?? null);
    }
    return ['current' => $current, 'overrides' => $this->dbRoleOverrides($names), 'shadow' => $shadow];
  }

  private function currentSettings(array $names): array
  {
    if ($names === []) {
      return [];
    }
    $rows = Connector::readOnly($this->connector->connect(), <<<'SQL'
      SELECT name, setting, context, source, sourcefile
        FROM pg_settings
       WHERE name = ANY (string_to_array(:names, ','))
      SQL, ['names' => implode(',', $names)]);
    $out = [];
    foreach ($rows as $row) {
      $out[$row['name']] = $row;
    }
    return $out;
  }

  /** ALTER DATABASE/ROLE … SET wins over every configuration file and is invisible in pg_settings of this session. */
  private function dbRoleOverrides(array $names): array
  {
    if ($names === []) {
      return [];
    }
    $rows = Connector::readOnly($this->connector->connect(), <<<'SQL'
      SELECT split_part(cfg, '=', 1) AS name
           , coalesce('Datenbank ' || d.datname, 'alle Datenbanken') || ', ' || coalesce('Rolle ' || r.rolname, 'alle Rollen') AS target
        FROM pg_db_role_setting s
        LEFT JOIN pg_database d ON d.oid = s.setdatabase
        LEFT JOIN pg_roles r ON r.oid = s.setrole
       CROSS JOIN LATERAL unnest(s.setconfig) AS cfg
       WHERE split_part(cfg, '=', 1) = ANY (string_to_array(:names, ','))
      SQL, ['names' => implode(',', $names)]);
    $out = [];
    foreach ($rows as $row) {
      $out[$row['name']][] = "{$row['name']} ist per ALTER DATABASE/ROLE … SET für {$row['target']} gesetzt und überschreibt diese Datei dort.";
    }
    return $out;
  }

  /**
   * An include file only wins over earlier configuration files. Values from the server's
   * command line or from postgresql.auto.conf (ALTER SYSTEM) still take precedence.
   * sourcefile is only visible to superusers / pg_read_all_settings.
   */
  private function shadowedBy(?array $setting): ?string
  {
    if ($setting === null) {
      return null;
    }
    $source = (string) $setting['source'];
    $file = (string) ($setting['sourcefile'] ?? '');
    return match (true) {
      $source === 'command line' => 'wird derzeit über die Kommandozeile des Servers gesetzt (-c, Dienst- oder Container-Definition) und überschreibt diese Datei.',
      $source === 'environment variable' => 'wird derzeit über eine Umgebungsvariable gesetzt und überschreibt diese Datei.',
      str_ends_with($file, 'postgresql.auto.conf') => 'wird per ALTER SYSTEM gesetzt (postgresql.auto.conf) und überschreibt diese Datei; aufheben mit ALTER SYSTEM RESET.',
      $source === 'configuration file' && $file === '' => 'Herkunft nicht prüfbar (Rechte); vor dem Einspielen von Hand prüfen.',
      $source === 'configuration file' && basename($file) !== 'postgresql.conf' && basename($file) !== '90-pg-harden.conf'
        => 'ist derzeit in ' . Text::printable($file) . ' gesetzt; wird diese Datei nach 90-pg-harden.conf gelesen (Dateien in conf.d nach Namen sortiert; auch spätere Zeilen in postgresql.conf selbst), gilt weiter ihr Wert.',
      default => null,
    };
  }

  private function writeSql(array $failed, string $dir, array &$unplannable): array
  {
    $byDb = [];
    foreach ($failed as $r) {
      foreach ($r['findings'] as $f) {
        if ($f['fix_sql'] === null) {
          continue;
        }
        $db = $f['database'] ?? $this->connector->entry;
        // A name with control characters could break out of the SQL comment, and SQL handed back by
        // the server could carry psql meta-commands (\!) or variables. Such findings are never planned.
        if (Text::hasControl($db) || Text::hasControl($f['object']) || str_contains($db, '\\')
          || !Text::isSafeStatement($f['fix_sql']) || !Text::isSafeStatement($f['rollback_sql'])) {
          $unplannable[] = $r['title'] . ': ' . Report::findingLine($f);
          continue;
        }
        $prefix = $r['automation'] === 'auto' ? '' : '-- BESTÄTIGEN: ';
        $block = "-- {$r['id']}: " . $f['object'] . "\n" . $prefix . $f['fix_sql'];
        if ($f['rollback_sql'] !== null) {
          $block .= "\n-- Rückweg: " . $f['rollback_sql'];
        }
        $byDb[$db][] = $block;
      }
    }
    $files = [];
    $used = [];
    foreach ($byDb as $db => $stmts) {
      $db = (string) $db;
      // Case-insensitive file systems (Windows, macOS): Shop and shop must never share a file.
      $safe = preg_replace('/[^a-z0-9_.-]/', '_', strtolower($db));
      if ($safe !== $db || isset($used[$safe])) {
        $safe .= '_' . substr(sha1($db), 0, 8);
      }
      $used[$safe] = true;
      $file = "harden_$safe.sql";
      // No database name on a command line: psql reads "-d host=… dbname=…" as a connection string,
      // and shell quoting differs per platform. Instead the file refuses to run in the wrong database.
      $literal = "'" . str_replace("'", "''", $db) . "'";
      $body = '-- pg-harden ' . PG_HARDEN_VERSION . ' — für Datenbank ' . Text::printable($db) . ', erzeugt ' . date('Y-m-d H:i') . "\n"
        . '-- ' . PLAN_WARNING . "\n"
        . '-- ' . RESPONSIBILITY_NOTICE . "\n"
        . "-- Ausführen: Verbindung zur Zieldatenbank selbst herstellen, dann mit -v ON_ERROR_STOP=1 -f $file einspielen.\n"
        . "-- Die Datei bricht ab, wenn sie in einer anderen Datenbank läuft (Division durch null in der ersten Anweisung).\n"
        . "-- Zeilen mit \"-- BESTÄTIGEN:\" sind auskommentiert: Auswirkung prüfen, dann freischalten.\n\n"
        . "BEGIN;\nSET LOCAL lock_timeout = '5s';\nSET LOCAL standard_conforming_strings = on;\n"
        . "SELECT 1 / (pg_catalog.current_database() = $literal)::int AS richtige_datenbank;\n\n"
        . implode("\n\n", $stmts) . "\n\nCOMMIT;\n";
      $files[] = $this->put($dir . '/' . $file, $body);
    }
    return $files;
  }

  private function writeManual(array $failed, array $unplannable, array $report, string $dir): string
  {
    $out = "# Manuelle Maßnahmen\n\nErzeugt von pg-harden " . PG_HARDEN_VERSION . ' am ' . date('d.m.Y H:i') . ".\n\n"
      . PLAN_WARNING . " Der Plan enthält Rollen-, Objekt- und Netznamen: vertraulich ablegen.\n\n"
      . RESPONSIBILITY_NOTICE . "\n";
    if ($unplannable !== []) {
      $out .= "\n## Nicht automatisch planbar\n\nDiese Objekte tragen Namen mit Steuer- oder Formatzeichen, oder das Korrektur-SQL "
        . "enthält Zeichen, die psql auswerten würde. Sie werden bewusst nicht in eine SQL-Datei geschrieben; Herkunft klären, "
        . "von Hand korrigieren.\n\n";
      foreach ($unplannable as $u) {
        $out .= '- ' . Text::markdown($u) . "\n";
      }
    }
    $incomplete = array_filter($report['results'], fn($r) => $r['incomplete']);
    if ($incomplete !== []) {
      $out .= "\n## Nicht vollständig geprüft\n\n";
      foreach ($incomplete as $r) {
        $out .= "- {$r['title']} ({$r['id']}): " . Text::markdown(implode('; ', $r['notes'])) . "\n";
      }
    }
    foreach (Report::sorted($failed) as $r) {
      $rule = $this->catalog->rules[$r['id']];
      if (!in_array($rule->fix()['type'], ['manual', 'hba'], true)) {
        continue;
      }
      $out .= "\n## {$r['title']} ({$r['id']}, " . Report::SEVERITY_LABEL[$r['severity']] . ")\n\n";
      $out .= ($rule->data['rationale'] ?? '') . "\n\n**Maßnahme:** " . ($rule->data['remediation'] ?? '') . "\n\n";
      if ($rule->fix()['type'] === 'hba') {
        $out .= 'Mit `apply` ausführbar (Rückweg und Schutz vor dem Aussperren inklusive): `--include-confirm=' . $r['id'] . "`.\n\n";
      }
      foreach ($r['findings'] as $f) {
        $out .= '- ' . Text::markdown(Report::findingLine($f)) . "\n";
      }
    }
    return $this->put($dir . '/MANUELL.md', $out);
  }
}

final class Verifier
{
  public static function isReport(mixed $r): bool
  {
    if (!is_array($r) || !is_array($r['meta'] ?? null) || !is_array($r['results'] ?? null) || !array_is_list($r['results'])
      || preg_match('/^pg-harden 0\.[23]\./', (string) ($r['meta']['tool'] ?? '')) !== 1
      || array_filter(['server', 'server_version', 'user', 'created_at'], fn($k) => isset($r['meta'][$k]) && !is_string($r['meta'][$k])) !== []) {
      return false;
    }
    foreach ($r['results'] as $res) {
      if (!is_array($res) || !is_string($res['id'] ?? null) || !is_string($res['title'] ?? null) || !is_string($res['status'] ?? null)
        || !is_array($res['findings'] ?? null)) {
        return false;
      }
      foreach ($res['findings'] as $f) {
        if (!is_array($f) || !is_string($f['object'] ?? null) || !(is_string($f['database'] ?? null) || ($f['database'] ?? null) === null)) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * A previous finding only counts as fixed if it was actually re-checked this time: for cluster
   * findings the rule must be fully evaluated, for database findings that database must be among the
   * rule's checked databases. Everything else is "not comparable" — never "fixed".
   */
  public static function compare(array $previous, array $current): array
  {
    $key = fn($r, $f) => json_encode([$r['id'], $f['database'] ?? null, $f['object']], JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    $collect = function (array $report) use ($key): array {
      $set = [];
      foreach ($report['results'] as $r) {
        if ($r['status'] !== 'fail') {
          continue;
        }
        foreach ($r['findings'] as $f) {
          $set[$key($r, $f)] = ['rule' => $r['id'], 'title' => $r['title'], 'severity' => $r['severity'] ?? null, 'object' => $f['object'], 'database' => $f['database'] ?? null];
        }
      }
      return $set;
    };
    $byId = [];
    foreach ($current['results'] as $r) {
      $byId[$r['id']] = $r;
    }
    $rechecked = function (array $item) use ($byId): bool {
      $r = $byId[$item['rule']] ?? null;
      if ($r === null || !in_array($r['status'], ['pass', 'fail'], true)) {
        return false;
      }
      return $item['database'] === null ? !$r['incomplete'] : in_array($item['database'], $r['checked_databases'], true);
    };
    $before = $collect($previous);
    $after = $collect($current);
    $fixed = [];
    $unknown = [];
    foreach (array_diff_key($before, $after) as $k => $item) {
      if ($rechecked($item)) {
        $fixed[$k] = $item;
      } else {
        $unknown[$k] = $item;
      }
    }
    $warnings = [];
    foreach (['server' => 'Server', 'server_version' => 'Version', 'user' => 'Benutzer'] as $field => $label) {
      if (($previous['meta'][$field] ?? null) !== ($current['meta'][$field] ?? null)) {
        $warnings[] = "$label weicht ab: " . ($previous['meta'][$field] ?? '?') . ' → ' . ($current['meta'][$field] ?? '?');
      }
    }
    if (($previous['meta']['databases'] ?? []) !== ($current['meta']['databases'] ?? [])) {
      $warnings[] = 'Geprüfte Datenbanken weichen ab.';
    }
    return [
      'previous_created_at' => $previous['meta']['created_at'] ?? '?',
      'warnings' => $warnings,
      'fixed' => array_values($fixed),
      'new' => array_values(array_diff_key($after, $before)),
      'open' => array_values(array_intersect_key($after, $before)),
      'not_comparable' => array_values($unknown),
    ];
  }

  public static function renderText(array $diff): string
  {
    $labels = [
      'fixed' => 'Behoben',
      'new' => 'Neu',
      'open' => 'Weiter offen',
      'not_comparable' => 'Nicht vergleichbar (diesmal nicht erneut geprüft)',
    ];
    $out = "\nVERGLEICH MIT DEM BERICHT VOM " . TextRenderer::when((string) $diff['previous_created_at']) . "\n";
    foreach ($diff['warnings'] as $w) {
      $out .= '  ACHTUNG: ' . TextRenderer::wrap(Text::printable($w), 11) . "\n";
    }
    $out .= '  ' . implode(' · ', array_map(fn($k) => $labels[$k] . ' ' . count($diff[$k]), array_keys($labels))) . "\n";
    foreach ($labels as $k => $label) {
      if ($diff[$k] === []) {
        continue;
      }
      $items = $diff[$k];
      // Most severe first, then by rule: the same order as the findings in the report.
      usort($items, fn($a, $b) => [Report::SEVERITY_ORDER[$a['severity'] ?? 'info'] ?? 3, $a['rule']]
        <=> [Report::SEVERITY_ORDER[$b['severity'] ?? 'info'] ?? 3, $b['rule']]);
      $out .= "\n  $label (" . count($items) . ")\n";
      // One line per rule, its places side by side (hba.trust: Zeile 117, Zeile 119, …).
      $byRule = [];
      foreach ($items as $x) {
        $byRule[$x['rule']]['severity'] ??= $x['severity'] ?? '';
        $byRule[$x['rule']]['title'] ??= $x['title'] ?? '';
        $byRule[$x['rule']]['where'][] = ($x['database'] !== null ? '[' . Text::printable($x['database']) . '] ' : '') . Text::printable($x['object']);
      }
      foreach ($byRule as $rule => $g) {
        $out .= '    ' . mb_str_pad(Report::SEVERITY_LABEL[$g['severity']] ?? '', 8) . mb_str_pad(Text::printable((string) $rule), 29) . ' '
          . TextRenderer::wrap(Text::printable($g['title']), 42) . "\n"
          . str_repeat(' ', 42) . '- ' . TextRenderer::wrap(implode(', ', $g['where']), 44) . "\n";
      }
    }
    return $out;
  }
}

final class App
{
  public static function main(array $argv): int
  {
    umask(0077);
    // A closed output pipe must not kill a writing command halfway (see Out).
    if (function_exists('pcntl_signal') && defined('SIGPIPE')) {
      pcntl_signal(SIGPIPE, SIG_IGN);
    }
    // Stack traces carry arguments (stored password verifiers, candidates): keep them out of every output.
    ini_set('display_errors', 'stderr');
    ini_set('zend.exception_ignore_args', '1');
    ini_set('log_errors', '0');
    // PHP warnings must never end up in a report or on stdout: treat them as errors (exit 2).
    // A deliberately suppressed call (@) stays suppressed.
    set_error_handler(function (int $no, string $msg, string $file, int $line): bool {
      if ((error_reporting() & $no) === 0) {
        return false;
      }
      throw new ErrorException($msg, 0, $no, $file, $line);
    });
    try {
      $opt = Options::parse($argv);
      if ($opt->has('help')) {
        return self::help();
      }
      if ($opt->has('extra-candidates')) {
        if (!in_array($opt->command, ['check', 'plan', 'verify', 'apply'], true)) {
          throw new HardenException('--extra-candidates gilt nur für check, plan, verify und apply.');
        }
        WeakPasswords::useExtra(ExtraCandidates::load((string) $opt->get('extra-candidates')));
      }
      $catalog = Catalog::load(__DIR__);
      return match ($opt->command) {
        'check' => self::check($opt, $catalog),
        'plan' => self::plan($opt, $catalog),
        'verify' => self::verify($opt, $catalog),
        'client' => self::client($opt, $catalog),
        'apply' => (new Applier(new Connector($opt), $catalog, $opt))->run(),
        'rollback' => (new Rollback(new Connector($opt), $opt))->run(),
        'rules' => self::rules($catalog),
        '', 'help' => self::help(),
        default => throw new HardenException('Unbekannter Befehl ' . Text::printable($opt->command)),
      };
    } catch (Throwable $e) {
      Out::err('pg-harden: ' . Text::printable(strtok($e->getMessage(), "\n") ?: get_class($e)) . "\n");
      return 2;
    }
  }

  private static function runCheck(Connector $connector, Options $opt, Catalog $catalog): array
  {
    $ctx = ServerContext::load($connector, $opt);
    $results = (new Checker($connector, $ctx, $catalog))->run();
    return Report::build($ctx, $catalog, $results, $opt, $connector);
  }

  private static function check(Options $opt, Catalog $catalog): int
  {
    $report = self::runCheck(new Connector($opt), $opt, $catalog);
    self::output($opt, $report);
    return Report::exitCode($report);
  }

  private static function plan(Options $opt, Catalog $catalog): int
  {
    $dir = $opt->get('dir') ?? throw new HardenException('plan braucht --dir=<neues oder leeres Verzeichnis>');
    Files::prepareDir($dir);
    $connector = new Connector($opt);
    $report = self::runCheck($connector, $opt, $catalog);
    $files = (new Planner($connector, $catalog))->write($report, $dir);
    Out::write(TextRenderer::render($report));
    Out::write("\nPlan geschrieben (nichts ausgeführt):\n  " . implode("\n  ", $files) . "\n");
    return Report::exitCode($report);
  }

  private static function verify(Options $opt, Catalog $catalog): int
  {
    $file = $opt->get('previous') ?? throw new HardenException('verify braucht --previous=<report.json>');
    if (!is_file($file) || !is_readable($file)) {
      throw new HardenException("$file ist nicht lesbar.");
    }
    if (filesize($file) > 52428800) {
      throw new HardenException("$file ist größer als 50 MB — kein pg-harden-Bericht.");
    }
    $previous = json_decode((string) file_get_contents($file), true);
    if (!Verifier::isReport($previous)) {
      throw new HardenException("$file ist kein pg-harden-Bericht ab Version 0.2.");
    }
    if (($previous['meta']['mode'] ?? 'server') !== 'server') {
      throw new HardenException("$file ist ein Client-Bericht — verify vergleicht nur Berichte von check.");
    }
    $report = self::runCheck(new Connector($opt), $opt, $catalog);
    $report['comparison'] = Verifier::compare($previous, $report);
    self::output($opt, $report);
    return Report::exitCode($report);
  }

  private static function client(Options $opt, Catalog $catalog): int
  {
    foreach (['host', 'port', 'dbname', 'sslmode', 'databases', 'dir', 'previous'] as $serverOnly) {
      if ($opt->has($serverOnly)) {
        throw new HardenException("--$serverOnly gilt nicht für client (keine Datenbankverbindung).");
      }
    }
    $ctx = ClientContext::resolve($opt);
    $report = Report::buildClient($ctx, $catalog, ClientChecker::run($catalog, $ctx));
    self::output($opt, $report);
    return Report::exitCode($report);
  }

  private static function rules(Catalog $catalog): int
  {
    Out::write(mb_str_pad('Kennung', 32) . mb_str_pad('Schwere', 9) . mb_str_pad('Stufe', 9) . "Titel\n");
    foreach ($catalog->rules as $rule) {
      Out::write(mb_str_pad($rule->id(), 32) . mb_str_pad(Report::SEVERITY_LABEL[$rule->severity()], 9)
        . mb_str_pad($rule->automation(), 9) . $rule->title() . "\n");
    }
    Out::write("\n" . count($catalog->rules) . " Regeln · Katalog {$catalog->version}\n");
    return 0;
  }

  private static function output(Options $opt, array $report): void
  {
    $content = match ($opt->get('format', 'text')) {
      'json' => Text::json($report, ascii: $opt->get('out') === null),
      'html' => HtmlRenderer::render($report),
      'text' => TextRenderer::render($report),
      default => throw new HardenException('--format muss text, json oder html sein'),
    };
    $out = $opt->get('out');
    if ($out !== null) {
      Files::write($out, $content);
      Out::write("Bericht geschrieben: $out (" . TextRenderer::findings($report['meta']['counts']['fail']) . ")\n");
    } else {
      Out::write($content);
    }
  }

  private static function help(): int
  {
    $version = PG_HARDEN_VERSION;
    $notice = wordwrap(RESPONSIBILITY_NOTICE, 100);
    $legal = wordwrap(LEGAL_NOTICE, 100);
    Out::write(<<<TXT
      pg-harden {$version} — prüft PostgreSQL gegen einen Regelkatalog, schreibt Änderungsvorschläge, vergleicht Berichte.
      check, plan, verify, client und rules schreiben nichts auf den Server. apply und rollback verändern ihn nur mit
      ausdrücklichem --execute (bzw. gegen ein Journal) — mit Sicherung, Prüfung durch den Server und Anmeldetest.

        check   Instanz prüfen                  --format=text|json|html --out=DATEI
        plan    Änderungsplan schreiben         --dir=NEUES_VERZEICHNIS (führt nichts aus)
        verify  erneut prüfen und vergleichen   --previous=report.json
        client  Rechner prüfen, von dem aus verbunden wird (ohne Datenbankverbindung)
                --user=KONTO (fremdes Konto: Administrator/root nötig)  --scan=VERZ1,VERZ2  --format=… --out=DATEI
        apply   Plan ausführen (Trockenlauf, bis --execute --dir=NEUES_VERZEICHNIS angegeben ist)
                --rules=ID,ID  --include-confirm=ID,ID (Regeln mit "confirm" einzeln freigeben)  --yes
        rollback  apply zurücknehmen: --dir=<Journal-Verzeichnis von apply>
        rules   Regelkatalog anzeigen

      Passwortprüfung: --extra-candidates=DATEI  eigene Begriffe (höchstens 100 Einträge, einer je Zeile, je höchstens 64 Zeichen, nur ASCII),
                       Datei nur für den Betreiber lesbar; gilt für check, plan, verify und apply

      Verbindung: --host --port --user --dbname --sslmode --databases=a,b
      Passwort über PGPASSWORD oder pgpass-Datei, nie auf der Kommandozeile.
      Exit: 0 ohne Befund · 1 Befunde · 3 unvollständig geprüft · 2 Abbruch

      {$notice}
      Berichte enthalten Rollen-, Objekt- und Netznamen: vertraulich behandeln.

      Bestimmungsgemäße Verwendung: {$legal}

      MIT-Lizenz, Copyright (c) 2026 Frank Glück (Glück IT) — siehe LICENSE.

      TXT);
    return 0;
  }
}

// Runs unless a test loads the classes as a library (tests/allowlist-test.php defines PG_HARDEN_LIBRARY before the require).
// A silent exit 0 would read as "no findings", so the default is to run.
if (!defined('PG_HARDEN_LIBRARY')) {
  exit(App::main($argv));
}
