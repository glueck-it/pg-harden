#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * pg-harden 0.4.1
 * Checks a PostgreSQL instance against a data-driven rule catalog, writes a change plan
 * and compares before/after reports.
 *
 * check/plan/client write nothing to the server by design (apply/rollback are the only writers, see
 * src/Apply.php): every check runs inside its own
 * BEGIN TRANSACTION READ ONLY … ROLLBACK, as a single server-side prepared statement
 * (no multi-statement SQL), with search_path = pg_catalog, pg_temp. The rule catalog is
 * trusted input (it ships with the tool); everything read from the server is not.
 * Behind a transaction-pooling PgBouncer session settings are not reliable — connect directly.
 *
 * usage:
 *   php pg-harden.php check  [connection] [-f PREVIOUS] [-o NAME]
 *   php pg-harden.php client [--user=ACCOUNT] [--scan=DIR,DIR] [-f PREVIOUS] [-o NAME]
 *   php pg-harden.php plan   [connection] --dir=NEW_OR_EMPTY_DIR
 *   php pg-harden.php apply  [connection] [--rules=ID,..] [--include-confirm=ID,..] [--execute --dir=NEW_DIR [--yes]]
 *   php pg-harden.php rollback [connection] --dir=APPLY_JOURNAL_DIR
 *   php pg-harden.php rules
 *
 * connection: --host --port --user --dbname (entry database, default postgres) --sslmode
 *             --databases=a,b (restrict database-scoped rules)
 *             psql-style as well: -h HOST -p PORT -U USER -d DBNAME, --username; long forms --host=db1 or --host db1,
 *             short forms -h db1 or -hdb1 (no "="). -U/--username always mean the database user (client: --user=ACCOUNT).
 *             Help: --help or -?
 * report:     without -o the text report goes to the terminal. -o NAME writes NAME.json and NAME.html; a name ending in .json,
 *             .html, .htm or .txt is that one file (any other dot belongs to the name: -o audit.261028). Placeholders as in
 *             log_filename: %Y %y %m %d %H %M %S, %% for a percent sign (-o audit.%y%m%d).
 *             -f NAME compares with an earlier report: reads NAME.json (or NAME if it ends in .json).
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

const PG_HARDEN_VERSION = '0.4.1';

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

  /** JSON goes to files only (reports, plans, journals): the terminal gets text, so no control sequence reaches it. */
  public static function json(mixed $data): string
  {
    $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;
    try {
      return json_encode($data, $flags) . "\n";
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
      // Windows: an owner keeps WRITE_DAC whatever icacls removes — a directory of another account is refused before its ACL is touched.
      if (Platform::windows() && !in_array(WindowsFacts::strictAcl($dir)['owner'] ?? null, array_filter([Platform::currentSid(), 'S-1-5-18', 'S-1-5-32-544']), true)) {
        throw new HardenException("$dir gehört einem anderen Konto oder sein Besitzer ist nicht prüfbar. Ein neues Verzeichnis angeben.");
      }
    } elseif (!@mkdir($dir, 0700, true)) {
      throw new HardenException("Verzeichnis $dir lässt sich nicht anlegen.");
    }
    self::lockDown($dir, isDir: true);
    // Windows: the owner keeps WRITE_DAC whatever icacls removed — a directory of another account is not used (as the posix check above).
    if (Platform::windows() && !WindowsFacts::isStrictlyPrivate($dir)) {
      throw new HardenException("$dir gehört einem anderen Konto oder lässt sich nicht auf dieses Konto, SYSTEM und die Administratoren beschränken. Ein neues Verzeichnis angeben.");
    }
  }

  /**
   * Restricts a directory or output file to the running account (plus SYSTEM and Administrators on Windows).
   * Prevents other local accounts under %TEMP% or user directories from reading reports, plans or journals.
   */
  public static function lockDown(string $path, bool $isDir = false): void
  {
    if (!Platform::windows()) {
      Fs::attempt(fn() => chmod($path, $isDir ? 0700 : 0600));
      return;
    }
    // Without the own SID the restriction would lock this account out of its own report or journal.
    $sid = Platform::currentSid() ?? throw new HardenException("Konto dieses Prozesses nicht bestimmbar (whoami) — Zugriffsrechte von $path werden nicht eingeschränkt.");
    $perm = $isDir ? '(OI)(CI)F' : 'F';
    $args = [Platform::systemTool('icacls.exe'), $path, '/inheritance:r', '/grant:r', "*S-1-5-18:$perm", '/grant:r', "*S-1-5-32-544:$perm", '/grant:r', "*$sid:$perm"];
    if (Platform::run($args)[0] !== 0) {
      throw new HardenException("Zugriffsrechte von $path lassen sich nicht einschränken (icacls).");
    }
  }
}

/**
 * Names given to -o (output) and -f (earlier report). Only .json, .html, .htm and .txt at the end choose a format; every other dot
 * belongs to the name (-o audit.261028 writes audit.261028.json and audit.261028.html). -o takes placeholders as log_filename in
 * PostgreSQL, a small strftime subset — no separate switch for a time stamp.
 */
final class ReportName
{
  private const FORMATS = ['json' => 'json', 'html' => 'html', 'htm' => 'html', 'txt' => 'text'];
  /** strftime placeholder => DateTimeInterface::format */
  private const PLACEHOLDERS = ['Y' => 'Y', 'y' => 'y', 'm' => 'm', 'd' => 'd', 'H' => 'H', 'M' => 'i', 'S' => 's'];

  /**
   * The files -o NAME writes, placeholders filled from $at. A name without a format ending is a stem for .json and .html.
   *
   * @return array<string, string> file => json|html|text
   */
  public static function outputs(string $name, DateTimeInterface $at): array
  {
    $name = (string) preg_replace_callback('/%(.?)/s', fn(array $m): string => $m[1] === '%' ? '%'
      : $at->format(self::PLACEHOLDERS[$m[1]] ?? throw new HardenException('-o: unbekannter Platzhalter %' . Text::printable($m[1])
        . ' (möglich sind %Y %y %m %d %H %M %S, %% für ein Prozentzeichen).')), $name);
    if (preg_match('~[/\\\\]$~', $name) === 1) {
      throw new HardenException('-o braucht einen Dateinamen, kein Verzeichnis: ' . Text::printable($name));
    }
    $format = self::format($name);
    // -o .json or -o . would write a hidden file ".json" or "..json": a name needs more than dots in front of its ending.
    if (trim(pathinfo($name, $format !== null ? PATHINFO_FILENAME : PATHINFO_BASENAME), '.') === '') {
      throw new HardenException('-o braucht einen Namen vor der Endung: ' . Text::printable($name));
    }
    return $format !== null ? [$name => $format] : [$name . '.json' => 'json', $name . '.html' => 'html'];
  }

  /** The file -f NAME reads: NAME.json, or NAME itself if it ends in .json. HTML and text cannot be compared. */
  public static function previous(string $name): string
  {
    $format = self::format($name);
    if ($format === null) {
      return $name . '.json';
    }
    if ($format !== 'json') {
      throw new HardenException('-f vergleicht mit dem JSON-Bericht, nicht mit ' . Text::printable($name)
        . ' — den Namen ohne Endung oder mit .json angeben.');
    }
    return $name;
  }

  private static function format(string $name): ?string
  {
    return self::FORMATS[strtolower(pathinfo($name, PATHINFO_EXTENSION))] ?? null;
  }
}

final class Options
{
  private const VALUED = ['host', 'port', 'user', 'dbname', 'sslmode', 'databases', 'output', 'file', 'dir', 'scan', 'rules', 'include-confirm', 'extra-candidates'];
  private const FLAGS = ['help', 'execute', 'yes'];
  /** Short options as psql spells them, in addition to the long names. -h is the host as in psql; help is --help or -?. */
  private const SHORT = ['h' => 'host', 'p' => 'port', 'U' => 'user', 'd' => 'dbname', 'o' => 'output', 'f' => 'file', '?' => 'help'];
  /** psql's long name for the database user; pg-harden calls it --user. */
  private const ALIAS = ['username' => 'user'];

  public string $command = '';
  private array $values = [];

  /**
   * --name=value, --name value, and the psql short forms -h db1 / -hdb1 (-p, -U, -d, -?). A value given as the next argument
   * never starts with "-": a forgotten value then fails instead of swallowing the next option.
   */
  public static function parse(array $argv): self
  {
    $o = new self();
    $args = array_values(array_slice($argv, 1));
    // As in psql the help wins wherever it stands: a broken option next to it must not hide it.
    if (in_array('--help', $args, true) || in_array('-?', $args, true)) {
      $o->values['help'] = true;
      return $o;
    }
    /** @var array<string, string> option => how it was written */
    $spelled = [];
    for ($i = 0; $i < count($args); $i++) {
      $arg = $args[$i];
      if (str_starts_with($arg, '--')) {
        $pair = explode('=', substr($arg, 2), 2);
        $written = '--' . $pair[0];
        $name = self::ALIAS[$pair[0]] ?? $pair[0];
        $value = $pair[1] ?? null;
      } elseif (strlen($arg) >= 2 && $arg[0] === '-') {
        $written = substr($arg, 0, 2);
        $name = self::SHORT[$arg[1]] ?? throw new HardenException('Unbekannte Option ' . Text::printable($written) . ' (siehe --help).');
        $value = strlen($arg) > 2 ? substr($arg, 2) : null;
      } elseif ($o->command === '') {
        $o->command = $arg;
        continue;
      } else {
        throw new HardenException('Unbekanntes Argument: ' . Text::printable($arg));
      }
      if ($name === 'password') {
        throw new HardenException('Passwörter gehören nicht auf die Kommandozeile (Prozessliste, Shell-Historie). PGPASSWORD oder pgpass-Datei verwenden.');
      }
      $valued = in_array($name, self::VALUED, true);
      if (!$valued && !in_array($name, self::FLAGS, true)) {
        throw new HardenException('Unbekannte Option ' . Text::printable($written) . ' (siehe --help).');
      }
      if (!$valued && $value !== null) {
        throw new HardenException(Text::printable($written) . ' ist ein Schalter und nimmt keinen Wert.');
      }
      if ($valued && $value === null) {
        $next = $args[$i + 1] ?? null;
        if ($next === null || $next === '' || str_starts_with($next, '-')) {
          throw new HardenException(Text::printable($written) . " braucht einen Wert ($written WERT oder --$name=WERT)" . ($name === 'host' ? '; die Hilfe ist --help oder -?' : '') . '.');
        }
        $value = $next;
        $i++;
      }
      // -h=db1 or --host==db1 would otherwise connect to the host "=db1": no value starts with "=".
      if ($valued && $value !== null && str_starts_with($value, '=')) {
        throw new HardenException(Text::printable($written) . ": der Wert beginnt mit = (gemeint war wohl --$name=WERT oder $written WERT).");
      }
      if ($valued && $value === '') {
        throw new HardenException(Text::printable($written) . " braucht einen Wert ($written WERT oder --$name=WERT).");
      }
      if (array_key_exists($name, $o->values)) {
        throw new HardenException("--$name ist mehrfach angegeben (auch als Kurzform oder psql-Name gezählt).");
      }
      $o->values[$name] = $value ?? true;
      $spelled[$name] = $written;
    }
    // Options without a command would print the help with exit code 0 — in a script a forgotten value ("--host check") then passes.
    if ($o->command === '' && $o->values !== []) {
      throw new HardenException('Kein Befehl angegeben (check, plan, client, apply, rollback, rules) — fehlt vor dem Befehl ein Wert, etwa nach ' . Text::printable((string) end($spelled)) . '?');
    }
    // For client --user is an account of this machine; -U and --username always mean the database user, as in psql.
    if ($o->command === 'client' && in_array($spelled['user'] ?? null, ['-U', '--username'], true)) {
      throw new HardenException($spelled['user'] . ' ist der Datenbankbenutzer; client prüft ein Konto dieses Rechners: --user=KONTO.');
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
    if (!WindowsFacts::isStrictlyPrivate($path)) {
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
   * anything not checked sets "incomplete" so neither the exit code nor a comparison (-f) can treat it as clean.
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
      ] + (isset($row['hba_line']) ? ['hba_line' => (int) $row['hba_line'], 'hba_type' => (string) ($row['hba_type'] ?? '')] : [])
        + (isset($row['hba_file']) ? ['hba_file' => (string) $row['hba_file']] : [])
        + (isset($row['hba_key']) ? ['hba_key' => (string) $row['hba_key']] : []);
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
  /** Sections after the findings, in report order; the text report prints the titles in capitals. */
  public const GROUP_TITLE = [
    'error' => 'Fehler bei der Prüfung',
    'info' => 'Zu sichten',
    'incomplete' => 'Ohne Befund, aber nicht vollständig geprüft',
    'skip' => 'Übersprungen',
    'pass' => 'Ohne Befund',
  ];

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

  /**
   * The outline both report formats share: findings by severity, then the sections of GROUP_TITLE, each in catalog order,
   * and the summary numbers of exactly these sections ("ohne Befund" counts only fully checked rules).
   *
   * @return array{kind: string, by_severity: array<string, list<array>>, groups: array<string, list<array>>, severities: list<string>, rest: string}
   */
  public static function summary(array $report): array
  {
    $bySeverity = array_fill_keys(array_keys(self::SEVERITY_ORDER), []);
    $groups = array_fill_keys(array_keys(self::GROUP_TITLE), []);
    foreach (self::sorted($report['results']) as $r) {
      match (true) {
        $r['status'] === 'fail' => $bySeverity[$r['severity']][] = $r,
        $r['status'] === 'pass' && $r['incomplete'] => $groups['incomplete'][] = $r,
        default => $groups[$r['status']][] = $r,
      };
    }
    $severities = [];
    foreach ($bySeverity as $sev => $list) {
      if ($list !== []) {
        $severities[] = count($list) . ' ' . self::SEVERITY_LABEL[$sev];
      }
    }
    $c = $report['meta']['counts'];
    $client = ($report['meta']['mode'] ?? 'server') === 'client';
    $compared = isset($report['comparison']);
    return [
      'kind' => ($client ? 'Client-Prüfung' : 'Prüfbericht') . ($compared ? ' mit Vergleich' : ''),
      'by_severity' => $bySeverity,
      'groups' => $groups,
      'severities' => $severities,
      'rest' => count($groups['pass']) . ' ohne Befund · ' . count($groups['incomplete']) . ' ohne Befund, aber nicht vollständig geprüft · '
        . "{$c['info']} zu sichten · {$c['skip']} übersprungen · {$c['error']} Fehler",
    ];
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
    $s = Report::summary($report);
    $out = 'pg-harden ' . PG_HARDEN_VERSION . " · {$s['kind']} · " . self::when($m['created_at'] ?? '') . "\n";
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

    ['by_severity' => $bySeverity, 'groups' => $groups, 'severities' => $severities, 'rest' => $rest] = $s;
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
    foreach (Report::GROUP_TITLE as $key => $title) {
      if ($groups[$key] !== []) {
        $out .= "\n" . mb_strtoupper($title) . ' (' . count($groups[$key]) . ")\n" . implode('', array_map(self::item(...), $groups[$key]));
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

  /**
   * "2026-10-24T20:25:03+00:00" (also with fractions) → "24.10.2026 20:25 (+00:00)". Only this exact form is read: a previous report
   * is a file of unknown origin, and the lenient parser would turn "now" or a value with a NUL into a plausible date. Anything else
   * is shown as it is.
   */
  public static function when(string $atom): string
  {
    // The pattern first: createFromFormat alone also takes two-digit years, zone names and "+99:99", and refuses a NUL with a
    // ValueError instead of returning false.
    if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?[+-](?:0\d|1[0-4]):[0-5]\d$/D', $atom, $m) === 1) {
      $d = DateTimeImmutable::createFromFormat(($m[1] ?? '') !== '' ? 'Y-m-d\TH:i:s.uP' : DATE_ATOM, $atom);
      if ($d !== false && DateTimeImmutable::getLastErrors() === false) {
        return $d->format('d.m.Y H:i') . ' (' . $d->format('P') . ')';
      }
    }
    return Text::printable($atom);
  }
}

/**
 * The report as one self-contained HTML file: the outline of the text report (header, summary, comparison, findings by
 * severity, the other sections, mappings, result, notices) with an overview on top, a colour per severity, a print
 * layout and dark mode. No external resource and no script; the CSP admits exactly the one stylesheet by its hash.
 */
final class HtmlRenderer
{
  /** Colour keys of the sections after the findings; class names come from fixed keys like these only, never from report data. */
  private const GROUP_KEY = ['error' => 'error', 'info' => 'review', 'incomplete' => 'incomplete', 'skip' => 'skip', 'pass' => 'pass'];
  private const COMPARISON_KEY = ['fixed' => 'pass', 'new' => 'high', 'open' => 'medium', 'not_comparable' => 'incomplete'];
  private const MAPPING_KEY = [
    'Befund' => 'high',
    'nicht vollständig geprüft' => 'incomplete',
    'Sichtung nötig' => 'review',
    'ohne Befund' => 'pass',
    'nicht anwendbar' => 'skip',
  ];
  /** Overview tiles after the severities: the words of the summary line. */
  private const TILE_LABEL = [
    'pass' => 'ohne Befund',
    'incomplete' => 'ohne Befund, aber nicht vollständig geprüft',
    'info' => 'zu sichten',
    'skip' => 'übersprungen',
    'error' => 'Fehler',
  ];

  /** Dark mode only on screen: a printout is always light. */
  private const STYLE = <<<'CSS'
    :root{color-scheme:light dark;
      --bg:#fff;--fg:#1f2328;--muted:#57606a;--line:#d0d7de;--panel:#f6f8fa;
      --high:#b42318;--high-bg:#fdeceb;--medium:#a24100;--medium-bg:#fff0e0;--low:#7a5800;--low-bg:#fcf3cf;
      --info:#0b57d0;--info-bg:#e8f0fe;--review:var(--info);--review-bg:var(--info-bg);--error:#7b2d9b;--error-bg:#f4e9fa;
      --incomplete:#0b6577;--incomplete-bg:#dff2f6;--skip:#57606a;--skip-bg:#eef1f4;--pass:#17703a;--pass-bg:#e5f4e9}
    @media screen and (prefers-color-scheme:dark){:root{
      --bg:#0f1216;--fg:#e6edf3;--muted:#9da7b3;--line:#30363d;--panel:#161b22;
      --high:#ff8b80;--high-bg:#3d1714;--medium:#ffab5e;--medium-bg:#3a230d;--low:#e8c547;--low-bg:#30280b;
      --info:#8ab4f8;--info-bg:#12233f;--error:#d2a8ff;--error-bg:#2b1a3d;
      --incomplete:#5fd0e3;--incomplete-bg:#0d2c33;--skip:#9da7b3;--skip-bg:#21262d;--pass:#6dd58c;--pass-bg:#0f2e19}}
    .k-high{--k:var(--high);--kb:var(--high-bg)}.k-medium{--k:var(--medium);--kb:var(--medium-bg)}
    .k-low{--k:var(--low);--kb:var(--low-bg)}.k-info{--k:var(--info);--kb:var(--info-bg)}
    .k-review{--k:var(--review);--kb:var(--review-bg)}.k-error{--k:var(--error);--kb:var(--error-bg)}
    .k-incomplete{--k:var(--incomplete);--kb:var(--incomplete-bg)}.k-skip{--k:var(--skip);--kb:var(--skip-bg)}
    .k-pass{--k:var(--pass);--kb:var(--pass-bg)}
    *{box-sizing:border-box}
    html{background:var(--bg)}
    body{margin:0 auto;max-width:72rem;padding:24px 16px 48px;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
      color:var(--fg);background:var(--bg)}
    h1{font-size:1.6rem;line-height:1.25;margin:.2rem 0 1rem}
    h1 .host{font-weight:400;overflow-wrap:anywhere}
    h2,h3{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem}
    h2{font-size:1.15rem;margin:2rem 0 .6rem;padding-bottom:.3rem;border-bottom:1px solid var(--line)}
    h3{font-size:1rem;margin:1.2rem 0 .4rem}
    code,.id{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:.86em}
    a{color:var(--info)}
    a:focus-visible{outline:2px solid var(--info);outline-offset:2px}
    .tool,.note{color:var(--muted)}
    .tool{margin:0;font-size:.9rem}
    dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem;margin:0 0 1rem}
    dl.meta dt{color:var(--muted)}
    dl.meta dd{margin:0;overflow-wrap:anywhere}
    dl.meta dd.warn{color:var(--high);font-weight:600}
    .confidential{margin:0;padding:.2rem .7rem;border-left:3px solid var(--line);color:var(--muted);font-size:.9rem}
    .toc ol{list-style:none;margin:1rem 0 0;padding:0;display:flex;flex-wrap:wrap;gap:.4rem}
    .toc a{display:inline-flex;align-items:center;gap:.4rem;padding:.2rem .65rem;border:1px solid var(--line);border-radius:999px;
      background:var(--panel);color:var(--fg);font-size:.88rem;text-decoration:none}
    .toc a:hover{border-color:var(--fg)}
    .dot{flex:none;display:inline-block;width:.7rem;height:.7rem;border-radius:50%;background:var(--k,var(--muted))}
    .count{display:inline-block;min-width:1.7em;padding:0 .4em;border:1px solid var(--line);border-radius:999px;background:var(--panel);
      font-size:.8rem;font-weight:600;text-align:center}
    .tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(9.5rem,1fr));gap:.5rem;margin:.6rem 0}
    .tile{display:block;padding:.55rem .8rem;border:1px solid var(--line);border-top:4px solid var(--k);border-radius:8px;
      background:var(--panel);color:var(--fg);text-decoration:none}
    .tile .n{display:block;font-size:1.6rem;font-weight:700;line-height:1.15;color:var(--k)}
    .tile .l{font-size:.85rem;color:var(--muted)}
    .tile.zero{border-top-color:var(--line)}
    .tile.zero .n{color:var(--muted)}
    a.tile:hover{border-color:var(--k)}
    @media (min-width:30rem){.tile-main{grid-column:span 2}}
    .bar{display:block;width:100%;height:14px;margin:.8rem 0 .2rem;border-radius:7px;background:var(--line)}
    .bar rect{fill:var(--k);stroke:var(--bg);stroke-width:2px}
    .rules{list-style:none;margin:0;padding:0}
    .rule{margin:.45rem 0;padding:.5rem .8rem;border:1px solid var(--line);border-left:4px solid var(--k,var(--line));border-radius:6px}
    section.k-pass .rule,section.k-skip .rule{margin:.25rem 0;padding:.25rem .8rem}
    .rule-head{margin:0;display:flex;flex-wrap:wrap;align-items:baseline;gap:.15rem .7rem}
    .rule-head .id{color:var(--muted);overflow-wrap:anywhere}
    .rule-title{font-weight:600}
    .rule .note{margin:.3rem 0 0;font-size:.9rem;overflow-wrap:anywhere}
    .rule .note::before{content:"→ " / ""}
    .findings{margin:.35rem 0 0;padding-left:1.2rem}
    .findings li{overflow-wrap:anywhere}
    .badge{display:inline-block;padding:.05rem .55rem;border-radius:999px;background:var(--kb);color:var(--k);
      font-size:.8rem;font-weight:600;white-space:nowrap}
    .chips{list-style:none;margin:.5rem 0;padding:0;display:flex;flex-wrap:wrap;gap:.4rem}
    .banner{margin:.6rem 0;padding:.6rem .9rem;border:1px solid var(--line);border-left:4px solid var(--k);border-radius:6px;background:var(--kb)}
    .banner strong{color:var(--k)}
    .ids{line-height:1.9}
    .alert{margin:.5rem 0;padding:.5rem .8rem;border:1px solid var(--high);border-radius:6px;background:var(--high-bg)}
    .alert strong{color:var(--high)}
    .table-wrap{overflow-x:auto}
    table{width:100%;margin:.4rem 0;border-collapse:collapse;font-size:.9rem}
    th,td{padding:.35rem .55rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
    th{color:var(--muted);font-weight:600}
    td{overflow-wrap:break-word;hyphens:auto}
    td code,td.id{hyphens:none}
    td.num,td.key{white-space:nowrap}
    .result{margin:2rem 0 0;padding:.7rem .9rem;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
    footer{margin-top:2rem;color:var(--muted);font-size:.9rem}
    footer h2{color:var(--fg)}
    @media (max-width:30rem){dl.meta{grid-template-columns:1fr;gap:0}dl.meta dd{margin-bottom:.4rem}}
    @media screen and (max-width:40rem){
      table.stack,table.stack tbody{display:block}
      table.stack thead{display:none}
      table.stack tr{display:block;padding:.45rem 0;border-bottom:1px solid var(--line)}
      table.stack td{display:block;padding:.1rem 0;border:0;overflow-wrap:anywhere}
      table.stack td.key,table.stack td.state{display:inline-block;margin-right:.5rem}
      table.stack td[data-label]::before{content:attr(data-label) ": ";color:var(--muted)}
    }
    @media (forced-colors:active){.dot,.bar rect{forced-color-adjust:none}.badge,.count{border:1px solid}}
    @page{margin:14mm 12mm}
    @media print{
      body{max-width:none;padding:0;font-size:9.5pt}
      .toc{display:none}
      a{color:inherit;text-decoration:none}
      *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
      h2,h3{break-after:avoid}
      .rule,.tile,.alert,.result,tr{break-inside:avoid}
      thead{display:table-header-group}
      .table-wrap{overflow:visible}
    }
    CSS;

  public static function render(array $report): string
  {
    $m = $report['meta'];
    $c = $m['counts'];
    $s = Report::summary($report);
    $client = ($m['mode'] ?? 'server') === 'client';
    $legal = $m['legal_notice'] ?? null;

    // Sections in the order of the text report; the table of contents follows them.
    $toc = [['summary', 'Zusammenfassung', null, null]];
    $body = '';
    if (isset($report['comparison'])) {
      $toc[] = ['comparison', 'Vergleich', null, null];
      $body .= self::comparison($report['comparison']);
    }
    $sections = [];
    foreach ($s['by_severity'] as $sev => $list) {
      $sections[] = ["findings-$sev", 'Befunde — ' . Report::SEVERITY_LABEL[$sev], $sev, $list];
    }
    foreach ($s['groups'] as $group => $list) {
      $sections[] = ["rules-$group", Report::GROUP_TITLE[$group], self::GROUP_KEY[$group], $list];
    }
    foreach ($sections as [$id, $title, $key, $list]) {
      if ($list !== []) {
        $toc[] = [$id, $title, count($list), $key];
        $body .= self::section($id, $title, $key, $list);
      }
    }
    $n = 0;
    foreach ($report['mappings'] as $map) {
      if ($map['controls'] !== []) {
        $id = 'mapping-' . ++$n;
        $toc[] = [$id, 'Zuordnung ' . $map['framework'], null, null];
        $body .= self::mapping($id, $map);
      }
    }

    // Header lines as in the text report.
    if ($client) {
      $fields = [['Rechner', $m['server'] . ' · Konto ' . $m['user'], false]];
    } else {
      $fields = [
        ['Server', $m['server'] . ' · PostgreSQL ' . $m['server_version'] . ' · Benutzer ' . $m['user'] . ($m['superuser'] ? ' (Superuser)' : '')
          . ' · ' . ($m['ssl'] ? 'TLS' : 'ohne TLS'), false],
        ['Umfang', 'Datenbanken ' . implode(', ', $m['databases']) . ' · Betriebssystem-Regeln '
          . ($m['local_server'] ? 'geprüft' : 'nicht geprüft (' . $m['local_note'] . ')'), false],
      ];
      foreach ($m['refused_databases'] as $db => $reason) {
        $fields[] = ['Nicht geprüft', $db . ' — ' . $reason, false];
      }
      if ($m['remote'] && !$m['certificate_verified']) {
        $fields[] = ['Achtung', 'Serverzertifikat nicht geprüft — für entfernte Hosts --sslmode=verify-full verwenden', true];
      }
    }
    $meta = '';
    foreach ($fields as [$label, $value, $warn]) {
      $meta .= '<dt>' . self::esc($label) . '</dt><dd' . ($warn ? ' class="warn"' : '') . '>' . self::esc($value) . '</dd>';
    }
    $meta .= '<dt>Katalog</dt><dd>' . self::esc($m['catalog']) . ' · <a href="#notices">'
      . ($legal !== null ? 'Hinweise zu Verwendung und Gewähr' : 'Hinweis zur Gewähr') . '</a> am Ende</dd>';

    // Overview: findings in total and by severity, then the other sections, then all rules as one bar.
    $firstFinding = array_key_first(array_filter($s['by_severity']));
    $tiles = self::tile($c['fail'] > 0 ? 'high' : 'pass', $c['fail'], $c['fail'] === 1 ? 'Befund' : 'Befunde', "findings-$firstFinding", true);
    $segments = [];
    foreach ($s['by_severity'] as $sev => $list) {
      if ($sev !== 'info' || $list !== []) {
        $tiles .= self::tile($sev, count($list), Report::SEVERITY_LABEL[$sev], "findings-$sev");
      }
      $segments[] = [$sev, count($list)];
    }
    foreach (self::TILE_LABEL as $group => $label) {
      $tiles .= self::tile(self::GROUP_KEY[$group], count($s['groups'][$group]), $label, "rules-$group");
    }
    foreach (self::GROUP_KEY as $group => $key) {
      $segments[] = [$key, count($s['groups'][$group])];
    }
    $result = TextRenderer::findings($c['fail']) . ($s['severities'] === [] ? '' : ' (' . implode(' · ', $s['severities']) . ')') . ' · ' . $s['rest'];
    $total = count($report['results']);
    $summary = '<section id="summary"><h2>Zusammenfassung</h2><div class="tiles">' . $tiles . '</div>'
      . self::bar($segments, $total, "Anteile aller $total Regeln: $result") . '</section>';

    $body = $summary . $body . '<p class="result"><strong>Ergebnis:</strong> ' . self::esc($result) . '</p>';
    return self::page('Der Bericht', $s['kind'], $m['server'], TextRenderer::when((string) ($m['created_at'] ?? '')), $meta, $toc, $body, $legal);
  }

  /**
   * The protocol of apply --execute (apply.html in the journal): outcome, planned changes, what was not done, the steps, the files
   * touched, the comparison before/after and where the journal lies. Built from the same data as the terminal output and the journal.
   *
   * @param array{started_at: string, finished_at: ?string, server: string, server_version: string, user: string, dir: string,
   *   outcome: string, plan: array, skipped_confirm: list<string>, skipped_other: list<array{0: string, 1: string}>, steps: list<array>,
   *   files: list<array>, sql: list<array>, before_counts: array, after: ?array, post_error: ?string} $log
   */
  public static function applyLog(array $log): string
  {
    [$state, $key, $text] = match ($log['outcome']) {
      'ok' => ['Ausgeführt', 'pass', 'Alle Schritte ohne Fehler; die Nachprüfung ist gelaufen.'],
      'warnings' => ['Ausgeführt mit Warnungen', 'medium', 'Die Schritte mit WARNUNG unten prüfen.'],
      'failed' => ['Fehlgeschlagen', 'high', 'Mindestens ein Schritt ist gescheitert — was geschah und was zurückgenommen wurde, nennen die Schritte unten.'],
      default => ['Abgebrochen', 'high', 'Der Lauf endete vorzeitig (Meldung im Terminal). Was bis dahin geschah, steht unten und im Journal.'],
    };
    // "Ausgeführt" says the steps worked, not that the instance is in order: findings left over are named in the same sentence.
    $open = $log['after']['meta']['counts']['fail'] ?? 0;
    if ($open > 0 && in_array($log['outcome'], ['ok', 'warnings'], true)) {
      $text .= ' ' . TextRenderer::findings($open) . ($open === 1 ? ' bleibt' : ' bleiben') . ' offen (Vergleich unten).';
    }
    $cmp = $log['after']['comparison'] ?? null;
    $tiles =self::tile($log['before_counts']['fail'] > 0 ? 'high' : 'pass', $log['before_counts']['fail'], 'Befunde vorher', '');
    if ($log['after'] !== null) {
      $fail = $log['after']['meta']['counts']['fail'];
      $tiles .= self::tile($fail > 0 ? 'high' : 'pass', $fail, 'Befunde nachher', '');
    }
    if ($cmp !== null) {
      foreach (Verifier::LABELS as $k => $label) {
        $tiles .= self::tile(self::COMPARISON_KEY[$k], count($cmp[$k]), $label, 'comparison');
      }
    }
    $toc = [['summary', 'Ergebnis', null, $key], ['changes', 'Geplante Änderungen', null, null]];
    $body = "<section id=\"summary\"><h2>Ergebnis</h2><p class=\"banner k-$key\"><strong>" . self::esc($state) . '</strong> — ' . self::esc($text) . '</p>'
      . "<div class=\"tiles\">$tiles</div></section>" . self::plannedChanges($log);

    if ($log['skipped_confirm'] !== [] || $log['skipped_other'] !== []) {
      $toc[] = ['skipped', 'Nicht ausgeführt', count($log['skipped_confirm']) + count($log['skipped_other']), 'skip'];
      $body .= '<section id="skipped"><h2>Nicht ausgeführt</h2>';
      if ($log['skipped_confirm'] !== []) {
        $body .= '<p>Brauchen eine Freigabe mit <code>--include-confirm=&lt;Kennung&gt;</code>:</p><p class="ids">'
          . implode(', ', array_map(fn($id) => '<code class="id">' . self::esc($id) . '</code>', $log['skipped_confirm'])) . '</p>';
      }
      if ($log['skipped_other'] !== []) {
        $rows = '';
        foreach ($log['skipped_other'] as [$id, $why]) {
          $rows .= '<tr><td class="key"><code class="id">' . self::esc($id) . '</code></td><td data-label="Grund">' . self::esc($why) . '</td></tr>';
        }
        $body .= ($log['skipped_confirm'] !== [] ? '<h3>Aus anderen Gründen</h3>' : '')
          . "<div class=\"table-wrap\"><table class=\"stack\"><thead><tr><th scope=\"col\">Regel</th><th scope=\"col\">Grund</th></tr></thead><tbody>$rows</tbody></table></div>";
      }
      $body .= '</section>';
    }

    $toc[] = ['steps', 'Schritte', count($log['steps']), null];
    $rows = '';
    foreach ($log['steps'] as $s) {
      $rows .= '<tr><td class="num">' . self::esc(self::clock((string) ($s['at'] ?? ''))) . '</td><td class="state">' . self::stepBadge((string) $s['status'])
        . '</td><td data-label="Phase">' . self::esc($s['phase']) . '</td><td data-label="Meldung">' . self::esc($s['message']) . '</td></tr>';
    }
    $body .= '<section id="steps"><h2>Schritte</h2>' . ($rows === '' ? '<p class="note">Keine Schritte protokolliert.</p>'
      : "<div class=\"table-wrap\"><table class=\"stack\"><thead><tr><th scope=\"col\">Zeit</th><th scope=\"col\">Status</th><th scope=\"col\">Phase</th>"
        . "<th scope=\"col\">Meldung</th></tr></thead><tbody>$rows</tbody></table></div>") . '</section>';

    if ($log['files'] !== []) {
      $toc[] = ['files', 'Dateien', count($log['files']), null];
      $rows = '';
      foreach ($log['files'] as $f) {
        $rows .= '<tr><td><code>' . self::esc($f['path']) . '</code></td><td data-label="Aktion">' . ($f['action'] === 'created' ? 'angelegt' : 'geändert')
          . '</td><td data-label="Sicherung">' . ($f['backup'] === null ? '—' : '<code>' . self::esc($f['backup']) . '</code>') . '</td></tr>';
      }
      $body .= '<section id="files"><h2>Dateien</h2><p class="note">Auf dem Server geändert oder angelegt; die Sicherungen liegen im Journal.</p>'
        . "<div class=\"table-wrap\"><table class=\"stack\"><thead><tr><th scope=\"col\">Pfad</th><th scope=\"col\">Aktion</th><th scope=\"col\">Sicherung</th>"
        . "</tr></thead><tbody>$rows</tbody></table></div></section>";
    }

    if ($cmp !== null) {
      $toc[] = ['comparison', 'Vergleich', null, null];
      $body .= self::comparison($cmp);
    } elseif ($log['post_error'] !== null) {
      $toc[] = ['comparison', 'Nachprüfung', null, 'high'];
      $body .= '<section id="comparison"><h2>Nachprüfung</h2><p class="alert"><strong>Nicht möglich:</strong> ' . self::esc($log['post_error']) . '</p></section>';
    }

    $toc[] = ['journal', 'Journal', null, null];
    $body .= '<section id="journal"><h2>Journal</h2><dl class="meta">' . self::fields([
      ['Verzeichnis', $log['dir']],
      ['Rückgängig', 'php pg-harden.php rollback --dir=' . $log['dir'] . ' (gleiche Verbindung)'],
      ['Dateien', 'apply.html (dieses Protokoll), apply-log.json (Protokoll der Schritte), report-before.json, report-after.json, backup/ (Sicherungen)'],
    ]) . '</dl></section>';

    $meta = self::fields([
      ['Server', $log['server'] . ' · PostgreSQL ' . $log['server_version'] . ' · Benutzer ' . $log['user']],
      ['Lauf', 'Ausführung · begonnen ' . TextRenderer::when($log['started_at'])
        . ' · ' . ($log['finished_at'] !== null ? 'beendet ' . TextRenderer::when($log['finished_at']) : 'nicht beendet')],
      ['Journal', $log['dir']],
    ]);
    return self::page('Das Protokoll', 'apply-Protokoll', $log['server'], TextRenderer::when($log['started_at']), $meta, $toc, $body, null, true);
  }

  /**
   * The protocol of rollback (next to rollback-log.json or rollback-attempt-….json in the journal): outcome, steps, journal.
   *
   * @param array{started_at: string, finished_at: string, server: string, server_version: string, user: string, dir: string,
   *   apply_started_at: string, ok: bool, steps: list<array{status: string, message: string}>, log_file: string} $log
   */
  public static function rollbackLog(array $log): string
  {
    [$state, $key, $text] = $log['ok']
      ? ['Rückweg abgeschlossen', 'pass', 'Das Journal ist damit abgeschlossen (rollback-log.json).']
      : ['Rückweg unvollständig', 'high', 'Schritte unten und Journal prüfen; derselbe Befehl wiederholt den Rückweg.'];
    $rows = '';
    foreach ($log['steps'] as $s) {
      $rows .= '<tr><td class="state">' . self::stepBadge((string) $s['status']) . '</td><td data-label="Meldung">' . self::esc($s['message']) . '</td></tr>';
    }
    $body = "<section id=\"summary\"><h2>Ergebnis</h2><p class=\"banner k-$key\"><strong>" . self::esc($state) . '</strong> — ' . self::esc($text) . '</p></section>'
      . '<section id="steps"><h2>Schritte</h2>' . ($rows === '' ? '<p class="note">Nichts zurückzunehmen.</p>'
        : "<div class=\"table-wrap\"><table class=\"stack\"><thead><tr><th scope=\"col\">Status</th><th scope=\"col\">Meldung</th></tr></thead>"
          . "<tbody>$rows</tbody></table></div>") . '</section>'
      . '<section id="journal"><h2>Journal</h2><dl class="meta">' . self::fields([
        ['Verzeichnis', $log['dir']],
        ['apply vom', TextRenderer::when($log['apply_started_at'])],
        ['Protokoll', $log['log_file']],
      ]) . '</dl></section>';
    $toc = [['summary', 'Ergebnis', null, $key], ['steps', 'Schritte', count($log['steps']), null], ['journal', 'Journal', null, null]];
    $meta = self::fields([
      ['Server', $log['server'] . ' · PostgreSQL ' . $log['server_version'] . ' · Benutzer ' . $log['user']],
      ['Lauf', 'begonnen ' . TextRenderer::when($log['started_at']) . ' · beendet ' . TextRenderer::when($log['finished_at'])],
      ['Journal', $log['dir']],
    ]);
    return self::page('Das Protokoll', 'rollback-Protokoll', $log['server'], TextRenderer::when($log['started_at']), $meta, $toc, $body, null, true);
  }

  /** The planned changes of apply as in the terminal, each SQL statement with its state from the journal. */
  private static function plannedChanges(array $log): string
  {
    $plan = $log['plan'];
    $out = '<section id="changes"><h2>Geplante Änderungen</h2>';
    if ($plan['conf'] === [] && $plan['hba'] === [] && $plan['sql'] === []) {
      return $out . '<p class="note">keine</p></section>';
    }
    if ($plan['conf'] !== []) {
      $rows = '';
      foreach ($plan['conf'] as $a) {
        $rows .= '<tr><td><code>' . self::esc($a['name']) . '</code></td><td data-label="Wert"><code>' . self::esc("'" . $a['value'] . "'") . '</code></td>'
          . '<td data-label="Regel"><code class="id">' . self::esc($a['rule']) . '</code>'
          . ($a['restart'] ? ' <span class="badge k-medium">Neustart nötig, wird nicht ausgeführt</span>' : '') . '</td></tr>';
      }
      $out .= '<h3>Parameter → <code>conf.d/90-pg-harden.conf</code></h3><div class="table-wrap"><table class="stack"><thead><tr>'
        . "<th scope=\"col\">Parameter</th><th scope=\"col\">Wert</th><th scope=\"col\">Regel</th></tr></thead><tbody>$rows</tbody></table></div>";
    }
    foreach ($plan['notes'] as $note) {
      $out .= '<p class="note"><strong>Hinweis:</strong> ' . self::esc($note) . '</p>';
    }
    if ($plan['hba'] !== []) {
      $rows = '';
      foreach ($plan['hba'] as $a) {
        $rows .= '<tr><td class="num">Zeile ' . self::esc($a['line']) . '</td><td data-label="Änderung">' . ($a['kind'] === 'type' ? 'Typ ' : 'Methode ')
          . self::esc(implode('/', $a['from']) . ' → ' . $a['to']) . '</td><td data-label="Regel"><code class="id">' . self::esc($a['rule']) . '</code></td></tr>';
      }
      $out .= '<h3><code>pg_hba.conf</code></h3><p class="note">Sicherung, Prüfung durch den Server, Anmeldetest nach dem Neuladen (der Test deckt nur die '
        . 'Anmeldung dieses Werkzeugs ab, nicht Anwendungen und andere Rollen).</p><div class="table-wrap"><table class="stack"><thead><tr>'
        . "<th scope=\"col\">Zeile</th><th scope=\"col\">Änderung</th><th scope=\"col\">Regel</th></tr></thead><tbody>$rows</tbody></table></div>";
    }
    // State of each statement from the journal; a statement the run never reached has no entry. NUL cannot occur in database names.
    $done = [];
    foreach ($log['sql'] as $q) {
      $done[$q['database'] . "\0" . $q['rule'] . "\0" . (string) ($q['fix_sql'] ?? '')] = $q['status'];
    }
    foreach ($plan['sql'] as $db => $items) {
      $rows = '';
      foreach ($items as $i) {
        [$label, $key] = match ($done[$db . "\0" . $i['rule'] . "\0" . (string) ($i['fix_sql'] ?? '')] ?? null) {
          'committed' => ['ausgeführt', 'pass'],
          'failed' => ['fehlgeschlagen', 'high'],
          'pending' => ['offen', 'incomplete'],
          default => ['nicht ausgeführt', 'skip'],
        };
        $rows .= '<tr><td class="key"><code class="id">' . self::esc($i['rule']) . '</code></td><td class="state"><span class="badge k-' . $key . '">' . $label
          . '</span></td><td data-label="Anweisung"><code>' . self::esc($i['fix_sql']) . '</code></td></tr>';
      }
      $out .= '<h3>SQL in Datenbank ' . self::esc($db) . '</h3><div class="table-wrap"><table class="stack"><thead><tr><th scope="col">Regel</th>'
        . "<th scope=\"col\">Stand</th><th scope=\"col\">Anweisung</th></tr></thead><tbody>$rows</tbody></table></div>";
    }
    return $out . '</section>';
  }

  /** Header fields as dt/dd pairs, values escaped. */
  private static function fields(array $fields): string
  {
    $out = '';
    foreach ($fields as [$label, $value]) {
      $out .= '<dt>' . self::esc($label) . '</dt><dd>' . self::esc($value) . '</dd>';
    }
    return $out;
  }

  /** Status of a journal step as a badge: OK, WARNUNG, FEHLER; anything else grey. */
  private static function stepBadge(string $status): string
  {
    $key = match ($status) {
      'OK' => 'pass',
      'WARNUNG' => 'medium',
      'FEHLER' => 'high',
      default => 'skip',
    };
    return "<span class=\"badge k-$key\">" . self::esc($status) . '</span>';
  }

  /** "2026-10-28T12:00:05+00:00" → "12:00:05"; anything else as it is. */
  private static function clock(string $atom): string
  {
    $d = preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/D', $atom) === 1 ? DateTimeImmutable::createFromFormat(DATE_ATOM, $atom) : false;
    return $d === false ? $atom : $d->format('H:i:s');
  }

  /**
   * The frame of every page: the CSP admitting only the stylesheet, the header with meta fields, confidentiality note and table of
   * contents, the sections, the notices. $toc lists [id, label, count|null, colour key|null] with fixed ids and keys; $meta and $body
   * are HTML whose values are already escaped.
   */
  private static function page(string $document, string $kind, string $server, string $when, string $meta, array $toc, string $body, ?string $legal, bool $runLog = false): string
  {
    $toc[] = ['notices', 'Hinweise', null, null];
    $nav = '';
    foreach ($toc as [$id, $label, $count, $key]) {
      $nav .= "<li><a href=\"#$id\">" . ($key !== null ? "<span class=\"dot k-$key\" aria-hidden=\"true\"></span>" : '') . self::esc($label)
        . ($count !== null ? " <span class=\"count\">$count</span>" : '') . '</a></li>';
    }
    $notices = '<footer id="notices"><h2>Hinweise</h2>'
      . ($legal !== null ? '<p><strong>Bestimmungsgemäße Verwendung:</strong> ' . self::esc($legal) . '</p>' : '')
      . '<p>' . self::esc(RESPONSIBILITY_NOTICE) . '</p></footer>';
    $style = self::STYLE;
    $hash = base64_encode(hash('sha256', $style, true));
    $title = self::esc('pg-harden — ' . $kind . ' ' . $server);
    $tool = self::esc('pg-harden ' . PG_HARDEN_VERSION . ' · ' . $kind . ' · ' . $when);
    $kindHtml = self::esc($kind);
    $serverHtml = self::esc($server);
    $documentHtml = self::esc($document);
    // Fixed text. A run log carries no legal notice, so the deletion advice of LEGAL_NOTICE ("zeitnah löschen") is repeated here
    $privacy = $runLog ? ' Rollennamen können personenbeziehbar sein; nach Abschluss zeitnah löschen.' : '';
    return <<<HTML
      <!doctype html>
      <html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{$hash}'; base-uri 'none'; form-action 'none'">
      <meta name="color-scheme" content="light dark">
      <title>{$title}</title>
      <style>{$style}</style>
      </head><body>
      <header>
      <p class="tool">{$tool}</p>
      <h1>{$kindHtml} <span class="host">{$serverHtml}</span></h1>
      <dl class="meta">{$meta}</dl>
      <p class="confidential">{$documentHtml} enthält Rollen-, Objekt- und Netznamen. Vertraulich ablegen und vor einer Weitergabe prüfen.{$privacy}</p>
      <nav class="toc" aria-label="Inhalt"><ol>{$nav}</ol></nav>
      </header>
      <main>
      {$body}
      </main>
      {$notices}
      </body></html>

      HTML;
  }

  /** Every value of the report goes through here: printable (control and format characters made visible), then HTML-escaped. */
  private static function esc(mixed $s): string
  {
    return htmlspecialchars(Text::printable((string) $s), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  }

  private static function tile(string $key, int $n, string $label, string $target, bool $main = false): string
  {
    $class = "tile k-$key" . ($main ? ' tile-main' : ($n === 0 ? ' zero' : ''));
    $inner = "<span class=\"n\">$n</span> <span class=\"l\">" . self::esc($label) . '</span>';
    return $n > 0 && $target !== '' ? "<a class=\"$class\" href=\"#$target\">$inner</a>" : "<div class=\"$class\">$inner</div>";
  }

  /** All rules as one stacked bar: geometry as SVG attributes, colour from the stylesheet (the CSP admits no style attribute). */
  private static function bar(array $segments, int $total, string $label): string
  {
    if ($total === 0) {
      return '';
    }
    $x = 0.0;
    $rects = '';
    foreach ($segments as [$key, $n]) {
      if ($n > 0) {
        $w = 100 * $n / $total;
        $rects .= sprintf('<rect class="k-%s" x="%.3F%%" y="0" width="%.3F%%" height="100%%"/>', $key, $x, $w);
        $x += $w;
      }
    }
    return '<svg class="bar" role="img" aria-label="' . self::esc($label) . "\" width=\"100%\" height=\"14\">$rects</svg>";
  }

  private static function section(string $id, string $title, string $key, array $list): string
  {
    return "<section id=\"$id\" class=\"k-$key\"><h2><span class=\"dot\" aria-hidden=\"true\"></span>" . self::esc($title)
      . ' <span class="count">' . count($list) . '</span></h2><ul class="rules">' . implode('', array_map(self::item(...), $list)) . '</ul></section>';
  }

  /** One rule: id, title, then notes (→) and findings, as in the text report. */
  private static function item(array $r): string
  {
    $out = '<li class="rule"><p class="rule-head"><code class="id">' . self::esc($r['id']) . '</code> <span class="rule-title">'
      . self::esc($r['title']) . '</span>'
      . ($r['incomplete'] && $r['status'] === 'fail' ? ' <span class="badge k-incomplete">nicht vollständig geprüft</span>' : '') . '</p>';
    foreach ($r['notes'] as $note) {
      $out .= '<p class="note">' . self::esc($note) . '</p>';
    }
    $findings = '';
    foreach ($r['findings'] as $f) {
      $findings .= '<li>' . self::esc(Report::findingLine($f)) . '</li>';
    }
    return $out . ($findings !== '' ? "<ul class=\"findings\">$findings</ul>" : '') . '</li>';
  }

  /** The comparison of check -f / client -f: warnings, the four counts, then one table per non-empty list (one row per rule). */
  private static function comparison(array $diff): string
  {
    $out = '<section id="comparison"><h2>Vergleich mit dem Bericht vom ' . self::esc(TextRenderer::when((string) $diff['previous_created_at'])) . '</h2>';
    foreach ($diff['warnings'] as $w) {
      $out .= '<p class="alert"><strong>Achtung:</strong> ' . self::esc($w) . '</p>';
    }
    $chips = '';
    foreach (Verifier::LABELS as $k => $label) {
      $chips .= '<li class="badge k-' . self::COMPARISON_KEY[$k] . '">' . self::esc($label) . ' ' . count($diff[$k]) . '</li>';
    }
    $out .= "<ul class=\"chips\">$chips</ul>";
    foreach (Verifier::grouped($diff) as $k => $byRule) {
      $rows = '';
      foreach ($byRule as $rule => $g) {
        // Only a known severity becomes a class name (Verifier::compare already drops unknown ones from the previous report).
        $sev = isset(Report::SEVERITY_LABEL[$g['severity']])
          ? '<span class="badge k-' . $g['severity'] . '">' . Report::SEVERITY_LABEL[$g['severity']] . '</span>' : '';
        $rows .= "<tr><td class=\"state\">$sev</td><td data-label=\"Regel\"><code class=\"id\">" . self::esc($rule) . '</code><div>' . self::esc($g['title'])
          . '</div></td><td data-label="Fundstellen">' . self::esc(implode(', ', $g['where'])) . '</td></tr>';
      }
      $out .= '<h3 class="k-' . self::COMPARISON_KEY[$k] . '"><span class="dot" aria-hidden="true"></span>' . self::esc(Verifier::LABELS[$k])
        . ' <span class="count">' . count($diff[$k]) . '</span></h3><div class="table-wrap"><table class="stack"><thead><tr><th scope="col">Stufe</th>'
        . "<th scope=\"col\">Regel</th><th scope=\"col\">Fundstellen</th></tr></thead><tbody>$rows</tbody></table></div>";
    }
    return $out . '</section>';
  }

  private static function mapping(string $id, array $map): string
  {
    $rows = '';
    foreach ($map['controls'] as $ctl) {
      $rows .= '<tr><td class="key"><code>' . self::esc($ctl['control']) . '</code></td><td class="state"><span class="badge k-'
        . (self::MAPPING_KEY[$ctl['state']] ?? 'skip') . '">' . self::esc($ctl['state']) . '</span></td><td class="num" data-label="ohne Befund">'
        . self::esc($ctl['rules_clean']) . '</td><td data-label="Thema">' . self::esc($ctl['title']) . '</td><td class="id" data-label="Regeln">'
        . self::esc(implode(', ', $ctl['rules'])) . '</td></tr>';
    }
    return "<section id=\"$id\"><h2>Zuordnung " . self::esc($map['framework'])
      . ($map['verified'] ? '' : ' <span class="badge k-incomplete">Kennungen ungeprüft</span>') . '</h2>'
      . '<p class="note">' . self::esc(MAPPING_DISCLAIMER) . ($map['verified'] ? '' : ' ' . self::esc($map['note'])) . '</p>'
      . '<div class="table-wrap"><table class="stack"><thead><tr><th scope="col">Kennung</th><th scope="col">Ergebnis der Regeln</th>'
      . '<th scope="col">ohne Befund</th><th scope="col">Thema</th><th scope="col">Regeln</th></tr></thead>'
      . "<tbody>$rows</tbody></table></div></section>";
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
      || preg_match('/^pg-harden (?:0\.(?:[2-9]|\d{2,})\.|[1-9]\d*\.)/', (string) ($r['meta']['tool'] ?? '')) !== 1
      || array_filter(['mode', 'server', 'server_version', 'user', 'created_at'], fn($k) => isset($r['meta'][$k]) && !is_string($r['meta'][$k])) !== []) {
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
    // hba findings name their line ("Zeile 12"), and a line inserted above shifts every number after it. A rule whose
    // findings all carry the line's selector in both reports (hba_key: file, type, databases, users, address and netmask —
    // not the method; for broken lines file and error) is matched by the selector instead: lines with the same selector
    // pair first by equal line number, the rest in their order. What is then left on both sides pairs by line number where
    // only the address differs, so a line narrowed in place stays open rather than "fixed" and "new"; a line replaced by one
    // for other databases or users is "fixed" and "new". Reports before 0.4.1 carry no selector and stay matched by line
    // number.
    $bySelector = [];
    foreach ([$previous, $current] as $report) {
      foreach ($report['results'] as $r) {
        if ($r['status'] === 'fail') {
          $bySelector[$r['id']] = ($bySelector[$r['id']] ?? true) && $r['findings'] !== []
            && array_filter($r['findings'], fn($f) => !is_string($f['hba_key'] ?? null)) === [];
        }
      }
    }
    $group = fn(array $r, array $f) => json_encode([$r['id'], $f['database'] ?? null, $f['hba_key']], JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    $members = [];
    foreach ([$previous, $current] as $side => $report) {
      foreach ($report['results'] as $r) {
        if ($r['status'] === 'fail' && ($bySelector[$r['id']] ?? false)) {
          foreach ($r['findings'] as $f) {
            $g = $group($r, $f);
            // Everything but the address (the last field): file, type, databases, users — a narrowed line keeps it. A key
            // without that shape (hba.errors: file and error text) stays whole.
            $pos = strrpos($f['hba_key'], ' ');
            $shaped = $pos !== false && preg_match('/:(?:local|host\w*) \[/', $f['hba_key']) === 1;
            $members[$g]['place'] = [$r['id'], $f['database'] ?? null, $shaped ? substr($f['hba_key'], 0, $pos) : $f['hba_key']];
            $members[$g][$side][] = $f['object'];
          }
        }
      }
    }
    // $slots[side][group][object]: the pair numbers handed out, in order; a number shared by both sides is one line.
    $slots = [[], []];
    $left = [[], []];
    $line = fn($object) => (int) preg_replace('/\D+/', '', (string) $object);
    $n = 0;
    foreach ($members as $g => $m) {
      $prev = $m[0] ?? [];
      $curr = $m[1] ?? [];
      usort($prev, fn($a, $b) => $line($a) <=> $line($b));
      usort($curr, fn($a, $b) => $line($a) <=> $line($b));
      $restPrev = [];
      foreach ($prev as $o) {
        $k = array_search($o, $curr, true);
        if ($k !== false) {
          unset($curr[$k]);
          $slots[0][$g][$o][] = $slots[1][$g][$o][] = ++$n;
        } else {
          $restPrev[] = $o;
        }
      }
      $curr = array_values($curr);
      $paired = min(count($restPrev), count($curr));
      for ($i = 0; $i < $paired; $i++) {
        $slots[0][$g][$restPrev[$i]][] = $slots[1][$g][$curr[$i]][] = ++$n;
      }
      foreach ([array_slice($restPrev, $paired), array_slice($curr, $paired)] as $side => $rest) {
        foreach ($rest as $o) {
          $slots[$side][$g][$o][] = ++$n;
          $left[$side][json_encode([...$m['place'], $o], JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR)][] = [$g, $o, count($slots[$side][$g][$o]) - 1];
        }
      }
    }
    foreach ($left[0] as $k => $list) {
      foreach ($list as [$g0, $o0, $i0]) {
        if (($left[1][$k] ?? []) === []) {
          break;
        }
        [$g1, $o1, $i1] = array_shift($left[1][$k]);
        $slots[1][$g1][$o1][$i1] = $slots[0][$g0][$o0][$i0];
      }
    }
    $collect = function (array $report, int $side) use ($bySelector, $group, &$slots): array {
      $set = [];
      foreach ($report['results'] as $r) {
        if ($r['status'] !== 'fail') {
          continue;
        }
        // The previous report is a file of unknown origin: a severity outside the known ones stays empty.
        $severity = is_string($r['severity'] ?? null) && isset(Report::SEVERITY_ORDER[$r['severity']]) ? $r['severity'] : null;
        foreach ($r['findings'] as $f) {
          $id = ($bySelector[$r['id']] ?? false)
            ? [$r['id'], $f['database'] ?? null, 'hba', array_shift($slots[$side][$group($r, $f)][$f['object']])]
            : [$r['id'], $f['database'] ?? null, $f['object']];
          $set[json_encode($id, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR)]
            = ['rule' => $r['id'], 'title' => $r['title'], 'severity' => $severity, 'object' => $f['object'], 'database' => $f['database'] ?? null];
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
    $before = $collect($previous, 0);
    $after = $collect($current, 1);
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
    $client = ($current['meta']['mode'] ?? 'server') === 'client';
    $fields = $client ? ['server' => 'Rechner', 'user' => 'Konto'] : ['server' => 'Server', 'server_version' => 'Version', 'user' => 'Benutzer'];
    foreach ($fields as $field => $label) {
      if (($previous['meta'][$field] ?? null) !== ($current['meta'][$field] ?? null)) {
        $warnings[] = "$label weicht ab: " . ($previous['meta'][$field] ?? '?') . ' → ' . ($current['meta'][$field] ?? '?');
      }
    }
    if (!$client && ($previous['meta']['databases'] ?? []) !== ($current['meta']['databases'] ?? [])) {
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

  public const LABELS = [
    'fixed' => 'Behoben',
    'new' => 'Neu',
    'open' => 'Weiter offen',
    'not_comparable' => 'Nicht vergleichbar (diesmal nicht erneut geprüft)',
  ];

  /**
   * The non-empty lists of a comparison, one entry per rule with its places side by side (hba.trust: Zeile 117, Zeile 119, …);
   * most severe first, then by rule: the same order as the findings in the report. Places are printable, titles raw.
   *
   * @return array<string, array<string, array{severity: string, title: string, where: list<string>}>>
   */
  public static function grouped(array $diff): array
  {
    $out = [];
    foreach (array_keys(self::LABELS) as $k) {
      $items = $diff[$k];
      usort($items, fn($a, $b) => [Report::SEVERITY_ORDER[$a['severity'] ?? 'info'] ?? 3, $a['rule']]
        <=> [Report::SEVERITY_ORDER[$b['severity'] ?? 'info'] ?? 3, $b['rule']]);
      foreach ($items as $x) {
        $out[$k][$x['rule']]['severity'] ??= $x['severity'] ?? '';
        $out[$k][$x['rule']]['title'] ??= $x['title'] ?? '';
        $out[$k][$x['rule']]['where'][] = ($x['database'] !== null ? '[' . Text::printable($x['database']) . '] ' : '') . Text::printable($x['object']);
      }
    }
    return $out;
  }

  public static function renderText(array $diff): string
  {
    $out = "\nVERGLEICH MIT DEM BERICHT VOM " . TextRenderer::when((string) $diff['previous_created_at']) . "\n";
    foreach ($diff['warnings'] as $w) {
      $out .= '  ACHTUNG: ' . TextRenderer::wrap(Text::printable($w), 11) . "\n";
    }
    $out .= '  ' . implode(' · ', array_map(fn($k) => self::LABELS[$k] . ' ' . count($diff[$k]), array_keys(self::LABELS))) . "\n";
    foreach (self::grouped($diff) as $k => $byRule) {
      $out .= "\n  " . self::LABELS[$k] . ' (' . count($diff[$k]) . ")\n";
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
        if (!in_array($opt->command, ['check', 'plan', 'apply'], true)) {
          throw new HardenException('--extra-candidates gilt nur für check, plan und apply.');
        }
        WeakPasswords::useExtra(ExtraCandidates::load((string) $opt->get('extra-candidates')));
      }
      foreach (['output' => '-o (--output)', 'file' => '-f (--file)'] as $key => $spelled) {
        if ($opt->has($key) && !in_array($opt->command, ['check', 'client'], true)) {
          throw new HardenException("$spelled gilt nur für check und client.");
        }
      }
      $catalog = Catalog::load(__DIR__);
      return match ($opt->command) {
        'check' => self::check($opt, $catalog),
        'plan' => self::plan($opt, $catalog),
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
    if ($opt->has('scan')) {
      throw new HardenException('--scan gilt nur für client.');
    }
    // Names and earlier report are settled before the run: a typo must not cost a full check.
    $files = self::outputFiles($opt, new DateTimeImmutable());
    $previous = self::previous($opt, 'server');
    $report = self::runCheck(new Connector($opt), $opt, $catalog);
    if ($previous !== null) {
      $report['comparison'] = Verifier::compare($previous, $report);
    }
    self::output($files, $report);
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

  /** The earlier report of -f, or null without -f. Its mode must match the command: a client report is compared by client. */
  private static function previous(Options $opt, string $mode): ?array
  {
    if (!$opt->has('file')) {
      return null;
    }
    $file = ReportName::previous((string) $opt->get('file'));
    // One handle, judged by fstat: an entry swapped after a size check for a device, a FIFO or a growing file is not read (see Fs::read).
    $json = Fs::read($file, 52428800) ?? throw new HardenException("$file ist nicht lesbar, keine reguläre Datei oder größer als 50 MB.");
    $previous = json_decode($json, true);
    if (!Verifier::isReport($previous)) {
      throw new HardenException("$file ist kein pg-harden-Bericht ab Version 0.2.");
    }
    $found = $previous['meta']['mode'] ?? 'server';
    if ($found !== $mode) {
      throw new HardenException(match ($found) {
        'client' => "$file ist ein Bericht von client — mit client -f vergleichen.",
        'server' => "$file ist ein Bericht von check — mit check -f vergleichen.",
        default => "$file hat einen unbekannten Berichtsmodus.",
      });
    }
    return $previous;
  }

  private static function client(Options $opt, Catalog $catalog): int
  {
    foreach (['host', 'port', 'dbname', 'sslmode', 'databases', 'dir'] as $serverOnly) {
      if ($opt->has($serverOnly)) {
        throw new HardenException("--$serverOnly gilt nicht für client (keine Datenbankverbindung).");
      }
    }
    $files = self::outputFiles($opt, new DateTimeImmutable());
    $previous = self::previous($opt, 'client');
    $ctx = ClientContext::resolve($opt);
    $report = Report::buildClient($ctx, $catalog, ClientChecker::run($catalog, $ctx));
    if ($previous !== null) {
      $report['comparison'] = Verifier::compare($previous, $report);
    }
    self::output($files, $report);
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

  /**
   * The files of -o at time $at (empty without -o). Fixed once at the start of the run: an unknown placeholder or a missing
   * directory fails before the check, and a run across midnight still writes where it was checked (-o reports/%y%m%d/audit).
   *
   * @return array<string, string> file => json|html|text
   */
  private static function outputFiles(Options $opt, DateTimeInterface $at): array
  {
    if (!$opt->has('output')) {
      return [];
    }
    $files = ReportName::outputs((string) $opt->get('output'), $at);
    foreach (array_keys($files) as $file) {
      if (!is_dir(dirname($file))) {
        throw new HardenException('Verzeichnis ' . Text::printable(dirname($file)) . ' für -o gibt es nicht.');
      }
    }
    return $files;
  }

  /**
   * Without -o the text report goes to the terminal; with -o the files fixed at the start of the run ($files, see outputFiles) are
   * written and the terminal names them. Everything is rendered and written to temporary files first, then put in place: a renderer
   * or a target that fails leaves no half set behind.
   *
   * @param array<string, string> $files file => json|html|text
   */
  private static function output(array $files, array $report): void
  {
    if ($files === []) {
      Out::write(TextRenderer::render($report));
      return;
    }
    $content = [];
    foreach ($files as $file => $format) {
      $content[$file] = match ($format) {
        'json' => Text::json($report),
        'html' => HtmlRenderer::render($report),
        'text' => TextRenderer::render($report),
      };
    }
    $tmp = [];
    $placed = [];
    try {
      foreach ($content as $file => $text) {
        $tmp[$file] = self::writeTemp($file, $text);
      }
      foreach ($tmp as $file => $t) {
        if (Fs::attempt(fn() => rename($t, $file)) !== true) {
          throw new HardenException("$file lässt sich nicht schreiben (Verzeichnis oder Eintrag gleichen Namens, der sich nicht ersetzen lässt)."
            . ($placed !== [] ? ' Bereits geschrieben: ' . implode(', ', $placed) . '.' : ''));
        }
        $placed[] = $file;
      }
    } finally {
      foreach ($tmp as $t) {
        Fs::attempt(fn() => file_exists($t) && unlink($t));
      }
    }
    Out::write('Bericht geschrieben (' . TextRenderer::findings($report['meta']['counts']['fail']) . "):\n  "
      . implode("\n  ", array_map(fn($f) => Text::printable($f), array_keys($files))) . "\n");
  }

  /** Writes $content to a new temporary file next to $out and returns its name; the caller puts it in place. */
  private static function writeTemp(string $out, string $content): string
  {
    // A new file of this account, restricted while still empty, then put in place: the report never carries inherited access
    // rights, and a handle another account kept open on an existing file of that name never sees the new content.
    // Created, restricted and written through one handle: nothing goes through the path between restricting and writing.
    $tmp = $out . '.' . bin2hex(random_bytes(6)) . '.tmp';
    $fh = Fs::attempt(fn() => fopen($tmp, 'x'));
    if ($fh === null) {
      throw new HardenException("$out lässt sich nicht anlegen (Verzeichnis nicht beschreibbar?).");
    }
    try {
      try {
        Files::lockDown($tmp);
        $written = Fs::attempt(fn() => fwrite($fh, $content)) === strlen($content);
        Fs::attempt(fn() => fsync($fh));
      } finally {
        $closed = Fs::attempt(fn() => fclose($fh)) === true;
      }
      if (!$written || !$closed) {
        throw new HardenException("$out konnte nicht vollständig geschrieben werden.");
      }
    } catch (Throwable $e) {
      Fs::attempt(fn() => file_exists($tmp) && unlink($tmp));
      throw $e;
    }
    return $tmp;
  }

  private static function help(): int
  {
    $version = PG_HARDEN_VERSION;
    $notice = wordwrap(RESPONSIBILITY_NOTICE, 100);
    $legal = wordwrap(LEGAL_NOTICE, 100);
    Out::write(<<<TXT
      pg-harden {$version} — prüft PostgreSQL gegen einen Regelkatalog, schreibt Änderungsvorschläge, vergleicht Berichte.
      check, plan, client und rules schreiben nichts auf den Server. apply und rollback verändern ihn nur mit
      ausdrücklichem --execute (bzw. gegen ein Journal) — mit Sicherung, Prüfung durch den Server und Anmeldetest.

        check   Instanz prüfen                  [-f FRÜHERER_BERICHT] [-o NAME]
        plan    Änderungsplan schreiben         --dir=NEUES_VERZEICHNIS (führt nichts aus)
        client  Rechner prüfen, von dem aus verbunden wird (ohne Datenbankverbindung)
                --user=KONTO (fremdes Konto: Administrator/root nötig)  --scan=VERZ1,VERZ2  [-f …] [-o …]
        apply   Plan ausführen (Trockenlauf, bis --execute --dir=NEUES_VERZEICHNIS angegeben ist)
                --rules=ID,ID  --include-confirm=ID,ID (Regeln mit "confirm" einzeln freigeben)  --yes
        rollback  apply zurücknehmen: --dir=<Journal-Verzeichnis von apply>
        rules   Regelkatalog anzeigen

      Bericht:  ohne -o als Text im Terminal
                -o NAME, --output NAME  schreibt NAME.json und NAME.html; endet NAME auf .json, .html, .htm oder .txt,
                         nur diese eine Datei (jeder andere Punkt gehört zum Namen: -o audit.261028)
                         Platzhalter wie log_filename: %Y %y %m %d %H %M %S, %% für ein Prozentzeichen (-o audit.%y%m%d;
                         in einer Windows-.bat-Datei jedes % verdoppeln: audit.%%y%%m%%d)
                         vorhandene Dateien gleichen Namens werden ersetzt (mehrmals am Tag: -o audit.%y%m%d-%H%M)
                -f NAME, --file NAME    mit einem früheren Bericht vergleichen (liest NAME.json, Datum eingesetzt): behoben, neu, weiter offen
                         check -f audit.261021 -o audit.261028

      Passwortprüfung: --extra-candidates=DATEI  eigene Begriffe (höchstens 100 Einträge, einer je Zeile, je höchstens 64 Zeichen, nur ASCII),
                       Datei nur für den Betreiber lesbar; gilt für check, plan und apply

      Verbindung: --host --port --user --dbname --sslmode --databases=a,b
                  wie bei psql auch -h HOST -p PORT -U BENUTZER -d DATENBANK (und --username); lang --host=db1 oder
                  --host db1, kurz -h db1 oder -hdb1 (ohne =). -U und --username sind immer der Datenbankbenutzer, bei client: --user=KONTO
      Passwort über PGPASSWORD oder pgpass-Datei, nie auf der Kommandozeile. Hilfe: --help oder -?
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
