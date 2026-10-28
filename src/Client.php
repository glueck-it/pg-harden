<?php
declare(strict_types=1);

/**
 * `pg-harden client`: checks the machine a person or service connects FROM — no database connection.
 * Looks at connection-service files, password files, client certificates, environment and scripts for
 * stored secrets and weak permissions. Secrets are never printed: a finding carries the place (file and
 * line, or variable name) and the kind of problem, nothing else.
 *
 * Reading another account's files (--user) needs administrator/root rights AND the permission to examine that
 * account — see LEGAL_NOTICE. The tool enforces the first part, the second is the operator's responsibility.
 *
 * MIT License, Copyright (c) 2026 Frank Glück (Glück IT) — see LICENSE. Provided "as is", without warranty.
 */

final class ClientContext
{
  /** @param string[] $extraScanDirs */
  public function __construct(
    public readonly string $account,
    public readonly string $home,
    public readonly ?string $appData,
    public readonly bool $isSelf,
    public readonly ?string $sid,
    public readonly array $extraScanDirs,
  ) {}

  /**
   * Windows, another account: its profile, below which nothing may lead elsewhere (Fs::windowsRedirected) — the administrator
   * cannot take on the account's identity there, so a junction the account placed would make it read for the account.
   */
  public function guardBase(): ?string
  {
    return Platform::windows() && !$this->isSelf ? $this->home : null;
  }

  public static function resolve(Options $opt): self
  {
    $requested = $opt->get('user');
    $extra = array_values(array_filter(array_map('trim', explode(',', (string) $opt->get('scan', '')))));
    foreach ($extra as $dir) {
      if (Text::hasControl($dir) || !Fs::isAbsolute($dir)) {
        throw new HardenException('--scan nimmt nur absolute Verzeichnisse ohne Steuerzeichen.');
      }
    }
    if (Platform::windows()) {
      return self::resolveWindows($requested, $extra);
    }
    if (!function_exists('posix_geteuid')) {
      throw new HardenException('client braucht die PHP-Erweiterung posix.');
    }
    $uid = posix_geteuid();
    $self = posix_getpwuid($uid);
    $pw = $requested === null ? $self : posix_getpwnam($requested);
    if (!is_array($pw)) {
      throw new HardenException($requested === null ? "Das ausführende Konto (UID $uid) hat keinen Eintrag in der Benutzerverwaltung." : 'Konto ' . Text::printable($requested) . ' gibt es auf diesem Rechner nicht.');
    }
    $isSelf = $pw['uid'] === $uid;
    if (!$isSelf && $uid !== 0) {
      throw new HardenException('--user für ein fremdes Konto setzt root-Rechte voraus (und die Berechtigung, dieses Konto zu prüfen).');
    }
    return new self($pw['name'], $pw['dir'], null, $isSelf, null, $extra);
  }

  private static function resolveWindows(?string $requested, array $extra): self
  {
    $current = (string) getenv('USERNAME');
    $domain = (string) getenv('USERDOMAIN');
    // "DOMAIN\name" is the own account only if the domain matches as well.
    $parts = $requested === null ? null : explode('\\', $requested, 2);
    $self = $requested === null
      || (count($parts) === 1 && strcasecmp($parts[0], $current) === 0)
      || (count($parts) === 2 && strcasecmp($parts[1], $current) === 0 && strcasecmp($parts[0], $domain) === 0);
    if ($self) {
      $home = (string) getenv('USERPROFILE');
      $appData = (string) getenv('APPDATA');
      if ($home === '') {
        throw new HardenException('USERPROFILE ist nicht gesetzt.');
      }
      return new self($current, $home, $appData !== '' ? $appData : $home . '\\AppData\\Roaming', true, null, $extra);
    }
    $info = Platform::powershell(<<<'PS'
      $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
      $out = @{ admin = $admin; sid = $null; profile = $null }
      if ($admin) {
        try {
          $sid = (New-Object Security.Principal.NTAccount([string]$d.user)).Translate([Security.Principal.SecurityIdentifier]).Value
          $out.sid = $sid
          $key = Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid)
          $out.profile = [Environment]::ExpandEnvironmentVariables([string]$key.ProfileImagePath)
        } catch {}
      }
      ConvertTo-Json -InputObject $out -Compress
      PS, ['user' => $requested]);
    if (($info['admin'] ?? false) !== true) {
      throw new HardenException('--user für ein fremdes Konto setzt Administratorrechte voraus (und die Berechtigung, dieses Konto zu prüfen).');
    }
    if (!is_string($info['profile'] ?? null) || $info['profile'] === '') {
      throw new HardenException('Profilverzeichnis von ' . Text::printable($requested) . ' nicht ermittelbar (Konto unbekannt oder noch nie angemeldet).');
    }
    return new self($requested, $info['profile'], $info['profile'] . '\\AppData\\Roaming', false, $info['sid'], $extra);
  }
}

/** Bounded text-file scanning: size limit, no binary files, never returns the matching text. */
final class SecretScan
{
  private const MAX_BYTES = 1048576;
  private const MAX_LINE = 4096;
  private const MAX_ENTRIES = 20000;
  private const MAX_SECONDS = 25;
  /** Dot-directories are skipped as a whole (their relevant files are named explicitly); so are data-only folders. */
  private const SKIP_DIRS = ['node_modules', 'vendor', 'AppData', 'Library', 'snap', '__pycache__', 'venv', 'Music', 'Pictures', 'Videos', 'Contacts', 'Favorites', 'Links', 'Searches', 'Saved Games', 'Downloads'];
  /** Cloud-sync folders: reading a "files on demand" placeholder starts a download — never scanned. */
  private const SYNC_DIR = '/^(OneDrive|Dropbox|Google Drive|Meine Ablage|My Drive|iCloud|Box|pCloud|MEGA|Nextcloud)\b/i';
  private const SCRIPT_EXT = ['sh', 'bash', 'zsh', 'ps1', 'psm1', 'bat', 'cmd', 'yml', 'yaml', 'env'];

  private const PATTERNS = [
    'setzt PGPASSWORD' => '/\bPGPASSWORD\b\s*[=:]/i',
    'Passwort in Verbindungs-URI' => '~postgres(?:ql)?://[^\s:@/]+:[^\s@/]+@~i',
    'POSTGRES_PASSWORD im Klartext' => '/\bPOSTGRES_PASSWORD\b\s*[=:]/i',
    'password= in Verbindungszeichenfolge' => '/\b(?:host|hostaddr|dbname|user)\s*=\s*\S+.*\bpassword\s*=\s*\S+/i',
  ];

  public int $visited = 0;
  public bool $truncated = false;
  public array $skippedSync = [];
  /** @var string[] places that could not be read in full */
  public array $skipped = [];
  private float $deadline;

  /** @param ?string $guardBase ClientContext::guardBase(): files below it are read only if nothing on the way leads elsewhere */
  public function __construct(public readonly ?string $guardBase = null)
  {
    $this->deadline = microtime(true) + self::MAX_SECONDS;
  }

  /**
   * Everything that is skipped is remembered in $skipped and reported as "not checked" — a file that was too big,
   * unreadable, binary or hit the regex limit must never look like "no finding".
   *
   * @return array<int, array{0: int, 1: string}> line number and kind of every hit
   */
  public function file(string $path, ?array $kinds = null): array
  {
    if (self::isSyncPath($path)) {
      $this->skippedSync[] = $path;
      return [];
    }
    $st = Fs::attempt(fn() => stat($path));
    if ($st === null || ($st['mode'] & 0170000) !== 0100000) {
      // Not a regular file (FIFO, device, socket) or not readable: never opened.
      $this->skipped[] = $path . ($st === null ? ' (nicht lesbar)' : ' (keine reguläre Datei)');
      return [];
    }
    if ($this->guardBase !== null && Fs::windowsRedirected($path, $this->guardBase)) {
      $this->skipped[] = $path . ' (' . ClientProbes::REDIRECTED . ' — nicht gelesen)';
      return [];
    }
    if ($st['size'] > self::MAX_BYTES) {
      $this->skipped[] = $path . ' (größer als 1 MiB)';
      return [];
    }
    $content = Fs::readGuarded($path, self::MAX_BYTES, $this->guardBase);
    if ($content === null) {
      $this->skipped[] = $path . ($this->guardBase !== null ? ' (nicht lesbar oder ' . ClientProbes::REDIRECTED . ')' : ' (nicht lesbar)');
      return [];
    }
    // Windows PowerShell 5.1 and Notepad write UTF-16 with a byte order mark.
    if (str_starts_with($content, "\xFF\xFE") || str_starts_with($content, "\xFE\xFF")) {
      $content = mb_convert_encoding($content, 'UTF-8', 'UTF-16');
    }
    if (str_contains($content, "\0")) {
      $this->skipped[] = $path . ' (Binärdatei oder unbekannte Kodierung)';
      return [];
    }
    $hits = [];
    foreach (preg_split('/\r\n|\n|\r/', $content) as $i => $line) {
      if (strlen($line) > self::MAX_LINE) {
        $this->skipped[] = $path . ':' . ($i + 1) . ' (Zeile länger als ' . self::MAX_LINE . ' Zeichen)';
        continue;
      }
      foreach (self::PATTERNS as $kind => $regex) {
        if ($kinds !== null && !in_array($kind, $kinds, true)) {
          continue;
        }
        $m = preg_match($regex, $line);
        if ($m === false) {
          $this->skipped[] = $path . ':' . ($i + 1) . ' (Mustervergleich abgebrochen)';
        } elseif ($m === 1) {
          $hits[] = [$i + 1, $kind];
        }
      }
    }
    return $hits;
  }

  /** Roots of cloud-sync clients as the system names them; reading a placeholder there starts a download. */
  private static function isSyncPath(string $path): bool
  {
    static $roots = null;
    $roots ??= array_values(array_filter(array_map(
      fn($v) => ($v = getenv($v)) !== false && $v !== '' ? Fs::canonical($v) : null,
      ['OneDrive', 'OneDriveCommercial', 'OneDriveConsumer'],
    )));
    $canon = Fs::canonical($path);
    foreach ($roots as $root) {
      if ($canon !== null && ($canon === $root || str_starts_with($canon, $root . '/'))) {
        return true;
      }
    }
    return false;
  }

  /** @return array<string, array<int, array{0: int, 1: string}>> path => hits, for scripts and compose files below $root */
  public function tree(string $root, int $maxDepth = 4): array
  {
    $out = [];
    $this->walk($root, $maxDepth, $out);
    return $out;
  }

  /**
   * PHP reports a Windows junction neither as a link nor as a directory, so walk does not enter one; this also keeps out a directory
   * that resolves anywhere but to its own name in its parent (same rule as Fs::windowsRedirected, without the realpath cache).
   */
  private static function isReparsePoint(string $parent, string $path): bool
  {
    return Fs::windowsRedirected($path, $parent);
  }

  private function walk(string $dir, int $depth, array &$out): void
  {
    $entries = Fs::entries($dir);
    if ($entries === null) {
      $this->skipped[] = $dir . ' (Verzeichnis nicht lesbar)';
      return;
    }
    foreach ($entries as $name) {
      if (++$this->visited > self::MAX_ENTRIES || microtime(true) > $this->deadline) {
        $this->truncated = true;
        return;
      }
      $path = $dir . DIRECTORY_SEPARATOR . $name;
      if (Fs::attempt(fn() => is_link($path)) === true) {
        continue;
      }
      if (Fs::attempt(fn() => is_dir($path)) === true) {
        if (preg_match(self::SYNC_DIR, $name) === 1) {
          $this->skippedSync[] = $path;
        } elseif ($depth > 0 && $name[0] !== '.' && !in_array($name, self::SKIP_DIRS, true) && !self::isReparsePoint($dir, $path)) {
          $this->walk($path, $depth - 1, $out);
        }
        continue;
      }
      if (Fs::attempt(fn() => is_file($path)) !== true) {
        continue;
      }
      $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
      $isCompose = preg_match('/^(docker-)?compose.*\.ya?ml$/i', $name) === 1;
      if ($isCompose || in_array($ext, self::SCRIPT_EXT, true) || $name === '.env' || str_starts_with($name, '.env.')) {
        $hits = $this->file($path);
        if ($hits !== []) {
          $out[$path] = $hits;
        }
      }
    }
  }
}

final class ClientProbes
{
  public const NAMES = [
    'service_file_password', 'pgpass_acl', 'pgpass_mode', 'pgpass_location', 'pgpass_superuser', 'pgpass_shadowed',
    'pgpass_loopback', 'env_pgpassword', 'secrets_in_files', 'cert_key_permissions', 'cert_expiry', 'psql_history',
  ];

  /** Principals that may read a password file on Windows: owner (the account itself), SYSTEM, Administrators, CREATOR OWNER. */
  private const ACL_ALLOWED = ['S-1-5-18', 'S-1-5-32-544', 'S-1-3-0'];

  /** Why a file in another account's profile was not read on Windows (Fs::windowsRedirected). */
  public const REDIRECTED = 'Weg im Profil über Junction/symbolischen Link bzw. nicht auflösbar';

  private static ?array $facts = null;
  private static ?string $factsKey = null;
  private static ?SecretScan $scan = null;

  /** @return array{findings: array[], unchecked: string[], notes: string[]} */
  public static function run(string $probe, ClientContext $c): array
  {
    $r = ['findings' => [], 'unchecked' => [], 'notes' => []];
    match ($probe) {
      'service_file_password' => self::serviceFilePassword($c, $r),
      'pgpass_acl' => self::pgpassAcl($c, $r),
      'pgpass_mode' => self::pgpassMode($c, $r),
      'pgpass_location' => self::pgpassLocation($c, $r),
      'pgpass_superuser' => self::pgpassEntries($c, $r, 'superuser'),
      'pgpass_shadowed' => self::pgpassEntries($c, $r, 'shadowed'),
      'pgpass_loopback' => self::pgpassEntries($c, $r, 'loopback'),
      'env_pgpassword' => self::envPgpassword($c, $r),
      'secrets_in_files' => self::secretsInFiles($c, $r),
      'cert_key_permissions' => self::certKeyPermissions($c, $r),
      'cert_expiry' => self::certExpiry($c, $r),
      'psql_history' => self::psqlHistory($c, $r),
    };
    return $r;
  }

  private static function finding(array &$r, string $object, string $detail): void
  {
    $r['findings'][] = ['database' => null, 'object' => $object, 'detail' => $detail, 'fix_sql' => null, 'rollback_sql' => null];
  }

  private static function mode(int $perms): string
  {
    return sprintf('%04o', $perms & 07777);
  }

  // ── locations ────────────────────────────────────────────────────────────

  /** libpq looks in PGSERVICEFILE, then the user's file, then the system file (PGSYSCONFDIR). */
  private static function serviceFiles(ClientContext $c): array
  {
    $files = [];
    if ($c->isSelf && ($env = getenv('PGSERVICEFILE')) !== false && $env !== '') {
      $files[] = $env;
    }
    $files[] = Platform::windows() ? ($c->appData ?? $c->home) . '\\postgresql\\.pg_service.conf' : $c->home . '/.pg_service.conf';
    $sys = $c->isSelf ? getenv('PGSYSCONFDIR') : false;
    foreach ($sys !== false && $sys !== '' ? [$sys] : (Platform::windows() ? [] : ['/etc/postgresql-common', '/etc/sysconfig/pgsql', '/etc']) as $dir) {
      $files[] = $dir . '/pg_service.conf';
    }
    return array_values(array_filter(array_unique($files), fn($f) => Fs::attempt(fn() => is_file($f)) === true));
  }

  private static function pgpassFile(ClientContext $c): string
  {
    if ($c->isSelf && ($env = getenv('PGPASSFILE')) !== false && $env !== '') {
      return $env;
    }
    return Platform::windows() ? ($c->appData ?? $c->home) . '\\postgresql\\pgpass.conf' : $c->home . '/.pgpass';
  }

  private static function certFiles(ClientContext $c): array
  {
    $dir = Platform::windows() ? ($c->appData ?? $c->home) . '\\postgresql' : $c->home . '/.postgresql';
    $sep = Platform::windows() ? '\\' : '/';
    $files = ['key' => [$dir . $sep . 'postgresql.key'], 'cert' => [$dir . $sep . 'postgresql.crt', $dir . $sep . 'root.crt']];
    if ($c->isSelf) {
      foreach (['PGSSLKEY' => 'key', 'PGSSLCERT' => 'cert', 'PGSSLROOTCERT' => 'cert'] as $env => $kind) {
        if (($v = getenv($env)) !== false && $v !== '') {
          $files[$kind][] = $v;
        }
      }
    }
    foreach ($files as $kind => $list) {
      $files[$kind] = array_values(array_filter(array_unique($list), fn($f) => Fs::attempt(fn() => is_file($f)) === true));
    }
    return $files;
  }

  private static function psqlHistoryFiles(ClientContext $c): array
  {
    $files = [];
    if ($c->isSelf && ($env = getenv('PSQL_HISTORY')) !== false && $env !== '') {
      $files[] = $env;
    }
    if (Platform::windows()) {
      $files[] = ($c->appData ?? $c->home) . '\\postgresql\\psql_history';
      $files[] = $c->home . '\\.psql_history';
    } else {
      $files[] = $c->home . '/.psql_history';
    }
    return array_values(array_filter(array_unique($files), fn($f) => Fs::attempt(fn() => is_file($f)) === true));
  }

  // ── Windows facts (one PowerShell run) ───────────────────────────────────

  private static function windowsFacts(ClientContext $c): array
  {
    $paths = array_values(array_unique(array_merge(
      [self::pgpassFile($c)], self::serviceFiles($c), self::psqlHistoryFiles($c), ...array_values(self::certFiles($c)),
    )));
    $key = $c->home . "\0" . ($c->appData ?? '') . "\0" . implode("\0", $paths);
    if (self::$facts !== null && self::$factsKey === $key) {
      return self::$facts;
    }
    self::$factsKey = $key;
    // Each file is opened once and both its final path (GetFinalPathNameByHandle) and its ACL (GetSecurityInfo) are read from that handle.
    $script = Platform::WIN_HANDLE_PS . "\n" . <<<'PS'
      $res = @{ env = @{ user = $false; machine = $false }; acls = @(); tasks = @() }
      try { $res.env.user = [bool][Environment]::GetEnvironmentVariable('PGPASSWORD', 'User') } catch {}
      try { $res.env.machine = [bool][Environment]::GetEnvironmentVariable('PGPASSWORD', 'Machine') } catch {}
      foreach ($path in @($d.paths)) {
        try {
          $res.acls += (Read-HandleAcl ([string]$path))
        } catch { $res.acls += @{ path = $path; error = $_.Exception.Message } }
      }
      try {
        foreach ($t in Get-ScheduledTask) {
          foreach ($a in $t.Actions) {
            $text = [string]$a.Execute + ' ' + [string]$a.Arguments
            if ($text -match 'PGPASSWORD\s*=') { $res.tasks += @{ name = $t.TaskPath + $t.TaskName; kind = 'setzt PGPASSWORD' } }
            elseif ($text -match 'postgres(ql)?://[^\s:@/]+:[^\s@/]+@') { $res.tasks += @{ name = $t.TaskPath + $t.TaskName; kind = 'Passwort in Verbindungs-URI' } }
          }
        }
      } catch {}
      ConvertTo-Json -InputObject $res -Depth 6 -Compress
      PS;
    return self::$facts = Platform::powershell($script, ['paths' => $paths]);
  }

  /** "a, b oder c": why a file was not read — with the redirect of Fs::windowsRedirected only where it applies (Windows, another account). */
  private static function unreadable(ClientContext $c, string ...$reasons): string
  {
    if ($c->guardBase() !== null) {
      $reasons[] = self::REDIRECTED;
    }
    $last = array_pop($reasons);
    return $reasons === [] ? $last : implode(', ', $reasons) . ' oder ' . $last;
  }

  /** Windows: findings for principals outside the allowed set that can reach the file. */
  private static function aclProblems(ClientContext $c, string $path, array &$r, string $what): void
  {
    // The ACL is read from the opened handle itself (GetSecurityInfo); if that handle's final path leads outside the examined
    // account's profile through a junction or link, its ACL belongs to another file and is not reported as this account's.
    $facts = self::windowsFacts($c);
    $base = $c->guardBase();
    foreach ($facts['acls'] ?? [] as $acl) {
      if (($acl['path'] ?? null) !== $path) {
        continue;
      }
      if (isset($acl['error']) || !is_string($acl['final'] ?? null)) {
        $r['unchecked'][] = Text::printable($path) . ': ' . ($base !== null && Fs::windowsRedirected($path, $base) ? self::REDIRECTED . ' — ACL nicht geprüft' : 'ACL nicht lesbar');
        return;
      }
      if ($base !== null && Fs::windowsRedirected($path, $base, $acl['final'])) {
        $r['unchecked'][] = Text::printable($path) . ': ' . self::REDIRECTED . ' — ACL nicht geprüft';
        return;
      }
      // The account itself (profile owner), the file owner, SYSTEM and Administrators may reach the file.
      $allowed = array_merge(self::ACL_ALLOWED, array_filter([$c->sid, $acl['owner'] ?? null, $c->isSelf ? self::currentSid() : null]));
      foreach ($acl['aces'] ?? [] as $ace) {
        if (($ace['type'] ?? '') === 'Allow' && ($ace['rights'] ?? '') !== 'Synchronize' && !in_array($ace['sid'] ?? '', $allowed, true)) {
          self::finding($r, $path, "$what: " . ($ace['name'] ?? $ace['sid'] ?? '?') . " hat Zugriff ({$ace['rights']})");
        }
      }
      return;
    }
  }

  private static function currentSid(): ?string
  {
    static $sid = false;
    if ($sid === false) {
      [$code, $out] = Platform::run([Platform::systemTool('whoami.exe'), '/user', '/fo', 'csv', '/nh']);
      $sid = $code === 0 && preg_match('/"(S-1-[0-9-]+)"/', $out, $m) === 1 ? $m[1] : null;
    }
    return $sid;
  }

  // ── service file ─────────────────────────────────────────────────────────

  private static function serviceFilePassword(ClientContext $c, array &$r): void
  {
    $files = self::serviceFiles($c);
    if ($files === []) {
      $r['notes'][] = 'Keine pg_service.conf gefunden';
      return;
    }
    foreach ($files as $file) {
      $content = Fs::readGuarded($file, 5242880, $c->guardBase());
      if ($content === null) {
        $r['unchecked'][] = Text::printable($file) . ': ' . self::unreadable($c, 'nicht lesbar', 'größer als 5 MiB');
        continue;
      }
      foreach (preg_split('/\r\n|\n|\r/', $content) as $i => $line) {
        if (preg_match('/^\s*password\s*=/i', $line) === 1) {
          self::finding($r, $file . ':' . ($i + 1), 'password= im Klartext (Wert wird nicht ausgegeben); libpq prüft die Rechte dieser Datei nicht');
        }
      }
    }
  }

  // ── pgpass ───────────────────────────────────────────────────────────────

  private static function pgpassAcl(ClientContext $c, array &$r): void
  {
    $file = self::pgpassFile($c);
    if (Fs::attempt(fn() => is_file($file)) !== true) {
      $r['notes'][] = 'Keine Passwortdatei gefunden (' . Text::printable($file) . ')';
      return;
    }
    self::aclProblems($c, $file, $r, 'Passwortdatei');
  }

  private static function pgpassMode(ClientContext $c, array &$r): void
  {
    $file = self::pgpassFile($c);
    $st = Fs::attempt(fn() => stat($file));
    if ($st === null) {
      $r['notes'][] = 'Keine Passwortdatei gefunden (' . Text::printable($file) . ')';
      return;
    }
    if (($st['mode'] & 0077) !== 0) {
      self::finding($r, $file, 'Modus ' . self::mode($st['mode']) . ': libpq ignoriert die Datei bei Zugriff für Gruppe oder andere (erwartet 0600) — Verbindungen fragen dann nach dem Passwort oder scheitern');
    }
  }

  private static function pgpassLocation(ClientContext $c, array &$r): void
  {
    $file = self::pgpassFile($c);
    $exists = Fs::attempt(fn() => is_file($file)) === true;
    if (!$exists) {
      $r['notes'][] = 'Keine Passwortdatei gefunden (' . Text::printable($file) . ')';
      return;
    }
    if (preg_match('~^(\\\\\\\\|//)~', $file) === 1) {
      self::finding($r, $file, 'liegt auf einer Netzfreigabe (UNC-Pfad) — die Datei verlässt den Rechner bei jeder Nutzung');
    }
    if (preg_match('~[\\\\/](OneDrive|Dropbox|Google Drive|iCloud Drive|iCloudDrive|Box|pCloud|MEGA|Nextcloud)\b~i', $file) === 1) {
      self::finding($r, $file, 'liegt in einem synchronisierten Cloud-Ordner — Passwörter werden in den Cloud-Dienst kopiert');
    }
    if (Platform::windows()) {
      // A roaming profile stores %APPDATA% on a server; the profile list names its path in CentralProfile.
      $sid = $c->isSelf ? self::currentSid() : $c->sid;
      if ($sid !== null) {
        [$code, $out] = Platform::run([Platform::systemTool('reg.exe'), 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\' . $sid, '/v', 'CentralProfile']);
        if ($code === 0 && preg_match('/CentralProfile\s+REG_SZ\s+(\S+)/i', $out, $m) === 1) {
          self::finding($r, $file, 'Das Konto hat ein servergespeichertes (Roaming-)Profil (' . Text::printable($m[1]) . ') — die Passwortdatei wird auf den Server kopiert');
        }
      }
    }
  }

  /**
   * Parses one password file: host:port:database:user:password; backslash escapes ":" and "\".
   * The password field is never kept.
   *
   * @return array<int, array{line: int, fields: string[]}> host, port, database, user
   */
  private static function pgpassLines(string $file, ?string $base): ?array
  {
    $content = Fs::readGuarded($file, 5242880, $base);
    if ($content === null) {
      return null;
    }
    $out = [];
    foreach (preg_split('/\r\n|\n|\r/', $content) as $i => $line) {
      if ($line === '' || $line[0] === '#') {
        continue;
      }
      $fields = [];
      $cur = '';
      for ($k = 0, $n = strlen($line); $k < $n; $k++) {
        if ($line[$k] === '\\' && $k + 1 < $n) {
          $cur .= $line[++$k];
        } elseif ($line[$k] === ':' && count($fields) < 4) {
          $fields[] = $cur;
          $cur = '';
        } else {
          $cur .= $line[$k];
        }
      }
      if (count($fields) === 4) {
        $out[] = ['line' => $i + 1, 'fields' => $fields];
      }
    }
    return $out;
  }

  private static function pgpassEntries(ClientContext $c, array &$r, string $kind): void
  {
    $file = self::pgpassFile($c);
    if (Fs::attempt(fn() => is_file($file)) !== true) {
      $r['notes'][] = 'Keine Passwortdatei gefunden (' . Text::printable($file) . ')';
      return;
    }
    $lines = self::pgpassLines($file, $c->guardBase());
    if ($lines === null) {
      $r['unchecked'][] = Text::printable($file) . ': ' . self::unreadable($c, 'nicht lesbar', 'größer als 5 MiB');
      return;
    }
    switch ($kind) {
      case 'superuser':
        foreach ($lines as $l) {
          [$host, , , $user] = $l['fields'];
          if (in_array($user, ['postgres', '*'], true) && $host === '*') {
            self::finding($r, "$file:{$l['line']}", 'Eintrag für ' . ($user === '*' ? 'jeden Benutzer' : 'den Superuser postgres') . ' gilt für jeden Host (*) — das Passwort wird an jeden Server gesendet, zu dem eine Verbindung gewünscht wird');
          }
        }
        break;
      case 'shadowed':
        // The first matching line wins: a later line whose fields are all matched by an earlier one never applies.
        $match = fn(string $earlier, string $later): bool => $earlier === '*' || $earlier === $later;
        foreach ($lines as $j => $later) {
          foreach (array_slice($lines, 0, $j) as $earlier) {
            if (array_map($match, $earlier['fields'], $later['fields']) === [true, true, true, true]) {
              self::finding($r, "$file:{$later['line']}", "wird nie benutzt: Zeile {$earlier['line']} passt zuerst");
              break;
            }
          }
        }
        break;
      case 'loopback':
        $hosts = array_column(array_column($lines, 'fields'), 0);
        if (in_array('localhost', $hosts, true)) {
          foreach (['127.0.0.1', '::1'] as $ip) {
            if (!in_array($ip, $hosts, true) && !in_array('*', $hosts, true)) {
              self::finding($r, $file, "Eintrag für localhost, aber keiner für $ip — Werkzeuge, die per IP-Adresse verbinden, finden kein Passwort");
            }
          }
        }
        break;
    }
  }

  // ── environment and files ────────────────────────────────────────────────

  private static function envPgpassword(ClientContext $c, array &$r): void
  {
    if ($c->isSelf && getenv('PGPASSWORD') !== false) {
      self::finding($r, 'Umgebung dieses Prozesses', 'PGPASSWORD ist gesetzt (Wert wird nicht ausgegeben; auch der Fall, wenn pg-harden selbst so aufgerufen wurde). Das Passwort steht im Prozessabbild und wird an Kindprozesse vererbt');
    }
    if (Platform::windows()) {
      if (!$c->isSelf) {
        $r['unchecked'][] = 'Umgebungsvariablen des Kontos ' . Text::printable($c->account) . ' (Registry-Hive nicht geladen)';
      } elseif (self::windowsFacts($c)['env']['user'] ?? false) {
        self::finding($r, 'Benutzer-Umgebungsvariable', 'PGPASSWORD ist dauerhaft für das Konto gesetzt (Wert wird nicht ausgegeben)');
      }
      if (self::windowsFacts($c)['env']['machine'] ?? false) {
        self::finding($r, 'System-Umgebungsvariable', 'PGPASSWORD ist für alle Konten dieses Rechners gesetzt (Wert wird nicht ausgegeben)');
      }
    } elseif (!$c->isSelf) {
      $r['notes'][] = 'Prozessumgebung eines fremden Kontos wird nicht gelesen; Profile und Dienstdateien unter „Passwörter in Dateien“';
    }
  }

  private static function scan(ClientContext $c): SecretScan
  {
    // One scan per run; a context with another profile (never within one run today) gets its own, never the other one's results.
    return self::$scan !== null && self::$scan->guardBase === $c->guardBase() ? self::$scan : self::$scan = new SecretScan($c->guardBase());
  }

  private static function secretsInFiles(ClientContext $c, array &$r): void
  {
    $scan = self::scan($c);
    $reported = [];
    $add = function (string $path, array $hits) use (&$r, &$reported): void {
      if (isset($reported[$path])) {
        return;
      }
      $reported[$path] = true;
      foreach ($hits as [$line, $kind]) {
        self::finding($r, $path . ':' . $line, $kind . ' (Wert wird nicht ausgegeben)');
      }
    };
    $named = [];
    if (Platform::windows()) {
      $named = [
        $c->home . '\\Documents\\WindowsPowerShell\\profile.ps1', $c->home . '\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1',
        $c->home . '\\Documents\\PowerShell\\profile.ps1', $c->home . '\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1',
      ];
    } else {
      foreach (['.bashrc', '.bash_profile', '.bash_login', '.profile', '.bash_aliases', '.zshrc', '.zprofile', '.zshenv', '.pam_environment', '.config/fish/config.fish'] as $f) {
        $named[] = $c->home . '/' . $f;
      }
      $named = array_merge($named, ['/etc/environment', '/etc/profile', '/etc/bash.bashrc', '/etc/crontab'],
        self::files('/etc/profile.d', '*'), self::files('/etc/cron.d', '*'),
        self::files('/etc/systemd/system', '*.service'), self::files($c->home . '/.config/systemd/user', '*.service'));
      foreach (Fs::entries('/etc/systemd/system') ?? [] as $entry) {
        if (str_ends_with($entry, '.service.d')) {
          $named = array_merge($named, self::files('/etc/systemd/system/' . $entry, '*.conf'));
        }
      }
    }
    foreach ($named as $file) {
      if (Fs::attempt(fn() => file_exists($file)) === true) {
        $add($file, $scan->file($file));
      }
    }
    // Home directory and the directories named with --scan (backup scripts, compose files).
    $roots = array_merge([$c->home], $c->extraScanDirs, Platform::windows() ? [] : ['/usr/local/bin', '/usr/local/sbin']);
    foreach (array_unique($roots) as $root) {
      if (Fs::attempt(fn() => is_dir($root)) !== true) {
        // Only a directory the operator asked for (or the profile itself) counts as "not checked"; default roots may simply not exist.
        if ($root === $c->home || in_array($root, $c->extraScanDirs, true)) {
          $r['unchecked'][] = Text::printable($root) . ': Verzeichnis nicht lesbar';
        }
        continue;
      }
      foreach ($scan->tree($root) as $path => $hits) {
        $add($path, $hits);
      }
    }
    if (!Platform::windows()) {
      self::crontab($c, $r);
    } else {
      foreach (self::windowsFacts($c)['tasks'] ?? [] as $task) {
        self::finding($r, 'Aufgabenplanung: ' . $task['name'], $task['kind'] . ' (Wert wird nicht ausgegeben)');
      }
    }
    foreach ($scan->skippedSync as $dir) {
      $r['notes'][] = 'Cloud-Ordner nicht durchsucht (Dateien könnten heruntergeladen werden): ' . Text::printable($dir) . ' — gezielt mit --scan angeben';
    }
    if ($scan->truncated) {
      $r['unchecked'][] = 'Suche nach ' . $scan->visited . ' Einträgen bzw. Zeitlimit abgebrochen — mit --scan auf bestimmte Verzeichnisse begrenzen';
    }
    foreach (array_slice($scan->skipped, 0, 20) as $place) {
      $r['unchecked'][] = Text::printable($place);
    }
    if (count($scan->skipped) > 20) {
      $r['unchecked'][] = '… und ' . (count($scan->skipped) - 20) . ' weitere Stellen';
    }
    $r['notes'][] = 'Durchsucht: Profil-Dateien, systemweite Profile/Cron/Dienstdateien, Skripte/Compose/.env bis Tiefe 4 unter ' . Text::printable($c->home) . ' und --scan; Passwort-Muster: PGPASSWORD, Verbindungs-URI, POSTGRES_PASSWORD, password= in Verbindungszeichenfolgen';
  }

  /** @return string[] files of one directory matching a pattern (no glob(): brackets in paths must not act as wildcards) */
  private static function files(string $dir, string $pattern): array
  {
    return array_values(array_map(fn($n) => $dir . '/' . $n, array_filter(Fs::entries($dir) ?? [], fn($n) => fnmatch($pattern, $n))));
  }

  private static function crontab(ClientContext $c, array &$r): void
  {
    $crontab = Platform::unixTool('crontab');
    if ($crontab === null) {
      return;
    }
    $cmd = $c->isSelf ? [$crontab, '-l'] : [$crontab, '-l', '-u', $c->account];
    [$code, $out] = Platform::run($cmd);
    if ($code !== 0) {
      return;
    }
    foreach (preg_split('/\r\n|\n|\r/', $out) as $i => $line) {
      foreach (['setzt PGPASSWORD' => '/\bPGPASSWORD\b\s*[=:]/i', 'Passwort in Verbindungs-URI' => '~postgres(?:ql)?://[^\s:@/]+:[^\s@/]+@~i'] as $kind => $regex) {
        if (preg_match($regex, $line) === 1) {
          self::finding($r, 'crontab von ' . Text::printable($c->account) . ':' . ($i + 1), $kind . ' (Wert wird nicht ausgegeben)');
        }
      }
    }
  }

  // ── client certificates ──────────────────────────────────────────────────

  private static function certKeyPermissions(ClientContext $c, array &$r): void
  {
    $keys = self::certFiles($c)['key'];
    if ($keys === []) {
      $r['notes'][] = 'Kein Client-Schlüssel gefunden';
      return;
    }
    foreach ($keys as $key) {
      if (Platform::windows()) {
        self::aclProblems($c, $key, $r, 'Client-Schlüssel');
        continue;
      }
      $st = Fs::attempt(fn() => stat($key));
      if ($st === null) {
        $r['unchecked'][] = Text::printable($key) . ': nicht lesbar';
        continue;
      }
      // libpq's own rule: 0600 for the user, 0640 if root owns the file.
      $limit = $st['uid'] === 0 ? 0037 : 0077;
      if (($st['mode'] & $limit) !== 0) {
        self::finding($r, $key, 'Schlüssel zu offen (Modus ' . self::mode($st['mode']) . '; erlaubt 0600' . ($st['uid'] === 0 ? ' oder 0640' : '') . ') — libpq verweigert die Verwendung');
      }
    }
  }

  private static function certExpiry(ClientContext $c, array &$r): void
  {
    $files = self::certFiles($c)['cert'];
    if ($files === []) {
      $r['notes'][] = 'Kein Client-Zertifikat gefunden';
      return;
    }
    if (!function_exists('openssl_x509_parse')) {
      $r['unchecked'][] = 'PHP-Erweiterung openssl fehlt — Ablaufdatum nicht prüfbar';
      return;
    }
    foreach ($files as $file) {
      $pem = Fs::readGuarded($file, 1048576, $c->guardBase());
      $info = $pem === null ? null : Fs::attempt(fn() => openssl_x509_parse($pem));
      if (!is_array($info)) {
        $r['unchecked'][] = Text::printable($file) . ': ' . self::unreadable($c, 'Zertifikat nicht lesbar');
        continue;
      }
      $left = (int) floor(($info['validTo_time_t'] - time()) / 86400);
      if ($left < 0) {
        self::finding($r, $file, 'Zertifikat ist seit ' . (-$left) . ' Tagen abgelaufen');
      } elseif ($left < 30) {
        self::finding($r, $file, "Zertifikat läuft in $left Tagen ab");
      } else {
        $r['notes'][] = Text::printable(basename($file)) . ": noch $left Tage gültig";
      }
    }
  }

  // ── psql history ─────────────────────────────────────────────────────────

  private static function psqlHistory(ClientContext $c, array &$r): void
  {
    $files = self::psqlHistoryFiles($c);
    if ($files === []) {
      $r['notes'][] = 'Keine psql-Historie gefunden';
      return;
    }
    $patterns = [
      'CREATE/ALTER ROLE … PASSWORD in Historie' => '/\b(?:CREATE|ALTER)\s+(?:ROLE|USER)\b[^\n;]*\bPASSWORD\s+(?:\'|\$[A-Za-z0-9_]*\$)/i',
      'Passwort in Verbindungs-URI' => '~postgres(?:ql)?://[^\s:@/]+:[^\s@/]+@~i',
      'setzt PGPASSWORD' => '/\bPGPASSWORD\b\s*[=:]/i',
    ];
    foreach ($files as $file) {
      if (Platform::windows()) {
        self::aclProblems($c, $file, $r, 'psql-Historie');
      } else {
        $st = Fs::attempt(fn() => stat($file));
        if ($st === null) {
          $r['unchecked'][] = Text::printable($file) . ': nicht lesbar';
          continue;
        }
        if (($st['mode'] & 0077) !== 0) {
          self::finding($r, $file, 'psql-Historie für Gruppe oder andere zugänglich (Modus ' . self::mode($st['mode']) . '; erwartet 0600)');
        }
      }
      $content = Fs::readGuarded($file, 5242880, $c->guardBase());
      if ($content === null) {
        $r['unchecked'][] = Text::printable($file) . ': ' . self::unreadable($c, 'nicht lesbar', 'größer als 5 MiB');
        continue;
      }
      foreach (preg_split('/\r\n|\n|\r/', $content) as $i => $line) {
        foreach ($patterns as $kind => $regex) {
          if (preg_match($regex, $line) === 1) {
            self::finding($r, $file . ':' . ($i + 1), $kind . ' (Wert wird nicht ausgegeben)');
            break;
          }
        }
      }
    }
  }
}
