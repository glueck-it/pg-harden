<?php
declare(strict_types=1);

/**
 * Operating-system checks for `check` (only when the tool runs on the machine of the server):
 * LocalServer proves that the data directory on this machine belongs to the connected instance,
 * OsProbes are the named probes the rules in rules/system.json refer to. Everything read from the file
 * system, from processes or from unit files is untrusted text and is printed through Text::printable.
 *
 * MIT License, Copyright (c) 2026 Frank Glück (Glück IT) — see LICENSE. Provided "as is", without warranty.
 */

/** Filesystem functions warn on failure and the global error handler turns warnings into exceptions. */
final class Fs
{
  /** Set when becomeRoot failed: the shutdown handler must not restore anything in a foreign identity. */
  public static bool $identityLost = false;

  public static function attempt(callable $fn): mixed
  {
    try {
      $result = $fn();
    } catch (ErrorException) {
      return null;
    }
    return $result === false ? null : $result;
  }

  public static function isAbsolute(string $path): bool
  {
    return str_starts_with($path, '/') || str_starts_with($path, '\\') || preg_match('/^[A-Za-z]:[\\\\\/]/', $path) === 1;
  }

  /** Comparable form of a path: resolved, forward slashes, case-insensitive on Windows. */
  public static function canonical(string $path): ?string
  {
    $real = self::attempt(fn() => realpath($path));
    if ($real === null) {
      return null;
    }
    // Only Windows uses "\" as a separator; elsewhere it is an ordinary character in a name.
    return Platform::windows() ? strtolower(str_replace('\\', '/', $real)) : $real;
  }

  /**
   * Runs $fn as root only where nobody else can change the way to $path, otherwise with the identity of the account
   * that can (the service account, see writerFor). A symlink or renamed directory planted by that account — even
   * between check and write — then only reaches what that account can reach; root does not follow it. Elsewhere
   * (Windows, not root) the function simply runs — which also makes a nested call inside a switched identity run
   * in that identity unchanged (euid is no longer 0), so it never switches back to root early.
   */
  public static function asOwnerOf(string $path, callable $fn): mixed
  {
    return self::runAs(fn() => self::writerFor($path), $fn);
  }

  /** As asOwnerOf, but with the identity readerFor chooses: for reading files another account may control (check, client). */
  public static function asReaderOf(string $path, callable $fn): mixed
  {
    return self::runAs(fn() => self::readerFor($path), $fn);
  }

  /** @param callable(): ?array $who identity for root, null: root itself */
  private static function runAs(callable $who, callable $fn): mixed
  {
    if (Platform::windows() || !function_exists('posix_geteuid') || posix_geteuid() !== 0) {
      return $fn();
    }
    $st = $who();
    if ($st === null) {
      return $fn();
    }
    // seteuid keeps root's supplementary groups (usually "root"): the account's own group list replaces them for the duration.
    if (!function_exists('posix_initgroups') || !posix_initgroups($st['name'], $st['gid'])) {
      throw new HardenException('Gruppen des Kontos ' . Text::printable($st['name']) . ' lassen sich nicht annehmen — nichts geändert.');
    }
    if (!posix_setegid($st['gid']) || !posix_seteuid($st['uid'])) {
      self::becomeRoot();
      throw new HardenException('Identität des Dateibesitzers lässt sich nicht annehmen — nichts geändert.');
    }
    try {
      return $fn();
    } finally {
      self::becomeRoot();
    }
  }

  /**
   * Back to root after asOwnerOf (also from the shutdown handler: exit() skips finally blocks): user, group, group list.
   * Checked afterwards: a process that stays in a foreign identity must not carry on — it ends at once (exit code 2), without
   * a restore in that identity; the shutdown handler then leaves the backups to the operator.
   */
  public static function becomeRoot(): void
  {
    try {
      posix_seteuid(0);
    } finally {
      posix_setegid(0);
      $root = posix_getpwuid(0);
      $groups = posix_initgroups(is_array($root) ? $root['name'] : 'root', 0);
    }
    if (posix_geteuid() !== 0 || posix_getegid() !== 0 || !$groups) {
      self::$identityLost = true;
      Out::err("pg-harden: Die Identität root ließ sich nicht wiederherstellen — Lauf sofort abgebrochen, Sicherungen und Journal von Hand prüfen.\n");
      exit(2);
    }
  }

  /** " (als Konto …)" for messages: which identity asOwnerOf chose, empty when nothing was switched. */
  public static function identityNote(): string
  {
    if (Platform::windows() || !function_exists('posix_geteuid') || posix_getuid() !== 0 || posix_geteuid() === 0) {
      return '';
    }
    $pw = posix_getpwuid(posix_geteuid());
    return ' (als Konto ' . Text::printable(is_array($pw) ? (string) $pw['name'] : (string) posix_geteuid())
      . ', dem ein Verzeichnis auf dem Weg gehört — die Datei muss für dieses Konto beschreibbar sein)';
  }

  /**
   * Reads a file of the server for apply/rollback: with the identity asOwnerOf chooses for the way, only a regular file, at most $max bytes.
   * A link the service account planted to a device or a FIFO then opens as that account, not as root.
   */
  public static function readServerFile(string $path, int $max = 5242880): ?string
  {
    return self::asOwnerOf($path, fn() => self::read($path, $max));
  }

  /**
   * Reads a file another account may control, for check and client (postmaster.pid, unit files, a person's .pgpass, scripts):
   * with the identity readerFor chooses, only a regular file, at most $max bytes. A link the account planted to a file of root
   * then reaches only what that account can read; null also when no identity can be determined.
   */
  public static function readGuarded(string $path, int $max = 5242880): ?string
  {
    // A relative path (PGPASSFILE=x) counts from the working directory, as for libpq; the walk needs it absolute.
    if (!Platform::windows() && !str_starts_with($path, '/') && ($cwd = self::attempt(fn() => getcwd())) !== null) {
      $path = rtrim($cwd, '/') . '/' . $path;
    }
    try {
      return self::asReaderOf($path, fn() => self::read($path, $max));
    } catch (HardenException) {
      return null;
    }
  }

  /**
   * Identity root takes on for $path, decided without a race: the way is walked from "/" with lstat. As long as every directory
   * belongs to root and is writable by nobody else, nothing on it can change afterwards — links there were placed by root and are
   * followed (at most 40). The first directory owned by another account decides: that account, for everything below it, whatever
   * it renames or links later. The path itself, existing in a root-only directory, decides by its own owner. A directory of root
   * writable by group or others is refused (anybody could plant something there that root would follow). Below the first directory
   * of another account nothing is refused any more: whatever is planted there reaches at most that account's rights. Only for root
   * on Unix (asOwnerOf).
   *
   * @return array{uid: int, gid: int, name: string}|null null: root may work on it itself
   */
  public static function writerFor(string $path): ?array
  {
    return self::walk($path, false);
  }

  /**
   * The identity root takes on to READ $path in check and client — writerFor's walk with one difference: a directory of root that
   * group or others may write to is not refused (a check must not stop at /tmp), it hands the decision on. With the sticky bit
   * only the owner of an entry may rename or remove it, so an existing next entry decides by its owner (a directory of root: the walk
   * goes on; a file or link of root: "nobody", see walk); a missing one could be created by anybody later, and without the sticky bit
   * anybody can swap any name — both are read as "nobody". An owner without an own account and group is read as "nobody" as well.
   * Only for root on Unix (asReaderOf).
   *
   * @return array{uid: int, gid: int, name: string}|null null: root may read it itself
   */
  public static function readerFor(string $path): ?array
  {
    return self::walk($path, true);
  }

  /** @return array{uid: int, gid: int, name: string}|null */
  private static function walk(string $path, bool $read): ?array
  {
    // Unix only: "\" is an ordinary character in a name there, replacing it would walk a different way than the kernel.
    if (!str_starts_with($path, '/')) {
      throw new HardenException('Pfad ist nicht absolut: ' . Text::printable($path) . ' — nichts geändert.');
    }
    $todo = array_values(array_filter(explode('/', $path), fn($s) => $s !== '' && $s !== '.'));
    $cur = '/';
    $links = 0;
    while (true) {
      $st = self::attempt(fn() => lstat($cur));
      if ($st === null || ($st['mode'] & 0170000) !== 0040000) {
        throw new HardenException('Verzeichnis ' . Text::printable($cur) . ' auf dem Weg zu ' . Text::printable($path) . ' ist nicht prüfbar — nichts geändert.');
      }
      if ($st['uid'] !== 0) {
        return self::identity($st['uid'], $read);
      }
      // Reading through a directory others may write to: the next entry decides (sticky bit), or nobody does.
      $shared = ($st['mode'] & 0022) !== 0;
      if ($shared && !$read) {
        throw new HardenException('Verzeichnis ' . Text::printable($cur) . ' auf dem Weg zu ' . Text::printable($path) . ' ist für Gruppe oder andere beschreibbar — nichts geändert.');
      }
      if ($todo === []) {
        return null;
      }
      if ($shared && ($st['mode'] & 01000) === 0) {
        return self::nobody();
      }
      $name = array_shift($todo);
      if ($name === '..') {
        $cur = dirname($cur);
        continue;
      }
      $next = rtrim($cur, '/') . '/' . $name;
      $lst = self::attempt(fn() => lstat($next));
      if ($lst === null) {
        if ($shared) {
          return self::nobody();
        }
        // Missing inside a root-only directory: only root could create it, so root may.
        if (self::definitelyAbsent($next)) {
          return null;
        }
        throw new HardenException('Eintrag ' . Text::printable($next) . ' ist nicht prüfbar — nichts geändert.');
      }
      if ($shared && $lst['uid'] !== 0) {
        return self::identity($lst['uid'], true);
      }
      $type = $lst['mode'] & 0170000;
      // A file or link of root there may be a name somebody else chose: a hard link to a file of root (fs.protected_hardlinks=0),
      // still or no longer the file's other name. Only a directory of root goes on as root (it cannot be hard-linked).
      if ($shared && $type !== 0040000) {
        return self::nobody();
      }
      if ($type === 0120000) {
        $target = self::attempt(fn() => readlink($next));
        if ($target === null || ++$links > 40) {
          throw new HardenException('Link ' . Text::printable($next) . ' ist nicht auflösbar — nichts geändert.');
        }
        $todo = array_merge(array_values(array_filter(explode('/', $target), fn($s) => $s !== '' && $s !== '.')), $todo);
        if (str_starts_with($target, '/')) {
          $cur = '/';
        }
        continue;
      }
      if ($type === 0040000) {
        $cur = $next;
        continue;
      }
      if ($todo !== []) {
        throw new HardenException(Text::printable($next) . ' ist kein Verzeichnis — nichts geändert.');
      }
      return $lst['uid'] === 0 ? null : self::identity($lst['uid'], $read);
    }
  }

  /**
   * The account with its own primary group, not the group of a file: a directory "postgres:root" must not lend the root group.
   * An owner without an account entry has no group list to take on — refused for writing, "nobody" for reading.
   * @return array{uid: int, gid: int, name: string}
   */
  private static function identity(int $uid, bool $read = false): array
  {
    $pw = function_exists('posix_getpwuid') ? posix_getpwuid($uid) : false;
    if (!is_array($pw) || (int) $pw['gid'] === 0) {
      if ($read) {
        return self::nobody();
      }
      throw new HardenException('Besitzer ' . $uid . ' hat kein eigenes Konto mit eigener Gruppe — mit dieser Identität wird nicht geschrieben, nichts geändert.');
    }
    return ['uid' => $uid, 'gid' => (int) $pw['gid'], 'name' => (string) $pw['name']];
  }

  /**
   * The account without rights for reading where no owner can be named: whatever was planted there reaches only what everybody may read.
   * @return array{uid: int, gid: int, name: string}
   */
  private static function nobody(): array
  {
    $pw = function_exists('posix_getpwnam') ? posix_getpwnam('nobody') : false;
    if (!is_array($pw) || (int) $pw['uid'] === 0 || (int) $pw['gid'] === 0) {
      throw new HardenException('Konto nobody fehlt — eine Datei, deren Besitzer nicht feststeht, wird nicht gelesen.');
    }
    return ['uid' => (int) $pw['uid'], 'gid' => (int) $pw['gid'], 'name' => 'nobody'];
  }

  /**
   * True only if a readable ancestor directory lists the path's next component as missing — "I cannot see it"
   * (no traverse right) must never be mistaken for "it does not exist".
   */
  public static function definitelyAbsent(string $path): bool
  {
    // As in canonical(): "\" is a separator on Windows only.
    $path = rtrim(Platform::windows() ? str_replace('\\', '/', $path) : $path, '/');
    for ($i = 0; $i < 12 && $path !== '' && $path !== dirname($path); $i++) {
      $parent = dirname($path);
      $names = self::entries($parent);
      if ($names !== null) {
        return !in_array(basename($path), $names, true);
      }
      $path = $parent;
    }
    return false;
  }

  /**
   * Reads at most $max bytes of a regular file; null if it is missing, unreadable, bigger or no regular file. Opened without
   * blocking ("n") and judged by fstat on that handle: a FIFO planted in its place would otherwise hang the run in open(), a device
   * would deliver without end. Files in /proc report the size 0 and are read up to $max.
   */
  public static function read(string $path, int $max = 5242880): ?string
  {
    // Only a regular file is opened at all (opening a device can act on it, a tape rewinds on close); the handle must then be that file.
    $before = self::attempt(fn() => stat($path));
    if ($before === null || ($before['mode'] & 0170000) !== 0100000 || $before['size'] > $max) {
      return null;
    }
    $fh = self::attempt(fn() => fopen($path, 'rbn'));
    if ($fh === null) {
      return null;
    }
    try {
      $st = self::attempt(fn() => fstat($fh));
      if ($st === null || ($st['mode'] & 0170000) !== 0100000 || $st['size'] > $max || $st['dev'] !== $before['dev'] || $st['ino'] !== $before['ino']) {
        return null;
      }
      // Regular files never block; Windows cannot switch the mode for files and reports false — not an error.
      self::attempt(fn() => stream_set_blocking($fh, true));
      $content = self::attempt(fn() => stream_get_contents($fh, $max + 1));
      return $content === null || strlen($content) > $max ? null : $content;
    } finally {
      fclose($fh);
    }
  }

  /** Octal text such as "0600" as reported by pg_settings; anything else counts as unknown. */
  public static function mode(string $text): ?int
  {
    return preg_match('/^0[0-7]{1,4}$/', $text) === 1 ? (int) octdec($text) : null;
  }

  /** @return string[]|null entries without . and .. */
  public static function entries(string $dir): ?array
  {
    $list = self::attempt(fn() => scandir($dir));
    return $list === null ? null : array_values(array_diff($list, ['.', '..']));
  }
}

final class Platform
{
  public static function windows(): bool
  {
    return DIRECTORY_SEPARATOR === '\\';
  }

  /**
   * Runs a program without a shell. Output goes to private temp files (pipes cannot be polled on Windows).
   *
   * @return array{0: int, 1: string} exit code, stdout
   */
  public static function run(array $command, int $timeoutSeconds = 30): array
  {
    $out = Fs::attempt(fn() => tempnam(sys_get_temp_dir(), 'pgh'));
    $err = Fs::attempt(fn() => tempnam(sys_get_temp_dir(), 'pgh'));
    if ($out === null || $err === null) {
      throw new HardenException('Temporäre Datei für die Programmausgabe lässt sich nicht anlegen.');
    }
    try {
      $pipes = [];
      // Helper programs never get the PG* variables (PGPASSWORD): they have no business with them.
      $env = array_filter(getenv(), fn($k) => !str_starts_with(strtoupper((string) $k), 'PG'), ARRAY_FILTER_USE_KEY);
      try {
        $proc = proc_open($command, [0 => ['pipe', 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $err, 'w']], $pipes, null, $env, ['bypass_shell' => true]);
      } catch (ErrorException) {
        $proc = false;
      }
      if (!is_resource($proc)) {
        throw new HardenException('Programm lässt sich nicht starten: ' . Text::printable(basename((string) $command[0])));
      }
      fclose($pipes[0]);
      $deadline = microtime(true) + $timeoutSeconds;
      $exit = null;
      while (true) {
        $status = proc_get_status($proc);
        if (!$status['running']) {
          $exit = $status['exitcode'];
          break;
        }
        if (microtime(true) > $deadline) {
          proc_terminate($proc, 9);
          proc_close($proc);
          throw new HardenException('Zeitüberschreitung bei ' . Text::printable(basename((string) $command[0])) . '.');
        }
        usleep(25000);
      }
      proc_close($proc);
      $text = Fs::attempt(fn() => file_get_contents($out, false, null, 0, 8388608));
      if ($text === null) {
        throw new HardenException('Programmausgabe nicht lesbar: ' . Text::printable(basename((string) $command[0])));
      }
      return [(int) $exit, str_starts_with($text, "\xEF\xBB\xBF") ? substr($text, 3) : $text];
    } finally {
      Fs::attempt(fn() => unlink($out));
      Fs::attempt(fn() => unlink($err));
    }
  }

  /** SID of the account running this process (Windows), null if it cannot be determined. */
  public static function currentSid(): ?string
  {
    if (!self::windows()) {
      return null;
    }
    [$code, $out] = self::run([self::systemTool('whoami.exe'), '/user', '/fo', 'csv', '/nh']);
    return $code === 0 && preg_match('/"(S-1-[0-9-]+)"/', $out, $m) === 1 ? $m[1] : null;
  }

  /** Windows system tools by absolute path: CreateProcess would otherwise look in the current directory first. */
  public static function systemTool(string $exe): string
  {
    if (!self::windows()) {
      return $exe;
    }
    $root = (string) getenv('SystemRoot');
    $root = $root !== '' ? $root : 'C:\\Windows';
    return $exe === 'powershell.exe' ? $root . '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' : $root . '\\System32\\' . $exe;
  }

  /** A Unix helper by absolute path in a system directory — root-owned, executable, not writable by others; null otherwise. */
  public static function unixTool(string $name): ?string
  {
    foreach (['/usr/bin', '/usr/sbin', '/bin', '/sbin'] as $dir) {
      $st = Fs::attempt(fn() => stat("$dir/$name"));
      if ($st !== null && ($st['mode'] & 0170000) === 0100000 && ($st['mode'] & 0111) !== 0 && $st['uid'] === 0 && ($st['mode'] & 0022) === 0) {
        return "$dir/$name";
      }
    }
    return null;
  }

  /** Whether a program of this name exists on PATH (no execution). */
  public static function has(string $program): bool
  {
    foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $dir) {
      foreach (self::windows() ? ['.exe', '.cmd', '.bat'] : [''] as $ext) {
        if ($dir !== '' && Fs::attempt(fn() => is_file($dir . DIRECTORY_SEPARATOR . $program . $ext)) === true) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Runs a PowerShell script (Windows PowerShell 5.1 is always present). The script reads its input as $d
   * (JSON, handed over base64-coded, never interpolated) and must print one JSON document.
   */
  public static function powershell(string $script, array $data): array
  {
    $payload = base64_encode(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    $full = "\$ErrorActionPreference = 'Stop'\n[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding(\$false)\n"
      . "\$d = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$payload')))\n" . $script;
    $encoded = base64_encode(mb_convert_encoding($full, 'UTF-16LE', 'UTF-8'));
    [$code, $out] = self::run([self::systemTool('powershell.exe'), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded], 60);
    $json = json_decode($out, true);
    if ($code !== 0 || !is_array($json)) {
      throw new HardenException('PowerShell-Abfrage fehlgeschlagen (Exit ' . $code . ').');
    }
    return $json;
  }
}

/** Proof that the instance we are connected to runs on this machine, plus the settings the probes need. */
final class LocalServer
{
  public const SETTINGS = [
    'data_directory', 'config_file', 'hba_file', 'ident_file', 'port', 'unix_socket_directories', 'unix_socket_permissions',
    'ssl', 'ssl_key_file', 'ssl_cert_file', 'logging_collector', 'log_directory', 'archive_mode',
  ];

  public const UNPROVEN = 'die Prozessnummer aus postmaster.pid passt nicht zum Elternprozess der eigenen Verbindung, zum Besitzer des Datenverzeichnisses oder zur Startzeit des Servers (/proc)';

  /**
   * $pid comes from postmaster.pid, a file of the service account: on Linux it counts only when proven() confirms it from /proc
   * (written by the kernel), otherwise it is null — the process probes would read another process as root. On Windows
   * WindowsFacts proves the same relation before it uses the process.
   */
  private function __construct(
    public readonly ?int $pid,
    public readonly int $backendPid,
    public readonly string $dataDir,
    public readonly array $settings,
  ) {}

  /** Setting as a path; relative values count from the data directory, as PostgreSQL itself resolves them. */
  public function path(string $name): ?string
  {
    $v = (string) ($this->settings[$name] ?? '');
    if ($v === '') {
      return null;
    }
    return Fs::isAbsolute($v) ? $v : $this->dataDir . '/' . $v;
  }

  public function setting(string $name): string
  {
    return (string) ($this->settings[$name] ?? '');
  }

  /** @return array{0: ?LocalServer, 1: string, 2: bool} server, note, whether "not local" leaves the check incomplete */
  public static function detect(PDO $pdo): array
  {
    $rows = Connector::readOnly($pdo, 'SELECT name, setting FROM pg_settings WHERE name = ANY (string_to_array(:names, \',\'))', ['names' => implode(',', self::SETTINGS)]);
    $settings = array_column($rows, 'setting', 'name');
    $own = Connector::readOnly($pdo, 'SELECT extract(epoch FROM pg_postmaster_start_time())::bigint AS t, pg_backend_pid() AS backend')[0];
    $start = (int) $own['t'];
    $dir = (string) ($settings['data_directory'] ?? '');
    if ($dir === '') {
      return [null, 'Datenverzeichnis nicht sichtbar', true];
    }
    if (Fs::attempt(fn() => is_dir($dir)) !== true) {
      if (Fs::definitelyAbsent($dir)) {
        return [null, 'Das Datenverzeichnis des Servers gibt es auf diesem Rechner nicht (entfernter Host oder Container) — Betriebssystem-Regeln nur auf dem Server selbst', false];
      }
      return [null, 'Das Datenverzeichnis ist von hier aus nicht sichtbar (fehlende Rechte?) — als Dienstkonto bzw. mit Administrator-/root-Rechten ausführen', true];
    }
    // Read with the service account's identity (its directory): a link or FIFO it placed there reaches only what it may read itself.
    $content = Fs::readGuarded($dir . '/postmaster.pid', 4096);
    if ($content === null) {
      return [null, 'postmaster.pid nicht lesbar — als Dienstkonto bzw. mit Administrator-/root-Rechten ausführen, um die Zugehörigkeit zu prüfen', true];
    }
    $lines = explode("\n", str_replace("\r", '', (string) $content));
    $same = (int) ($lines[0] ?? 0) > 0
      && Fs::canonical((string) ($lines[1] ?? '')) === Fs::canonical($dir)
      && abs((int) ($lines[2] ?? 0) - $start) <= 5
      && (string) (int) ($lines[3] ?? 0) === (string) ($settings['port'] ?? '');
    if (!$same) {
      return [null, 'postmaster.pid dieses Rechners gehört nicht zur verbundenen Instanz (anderer Server oder Container) — Betriebssystem-Regeln nur auf dem Server selbst', false];
    }
    $pid = (int) $lines[0];
    $backend = (int) $own['backend'];
    if (Platform::windows()) {
      return [new self($pid, $backend, $dir, $settings), 'lokal (Prozess ' . $pid . ', Nachweis über die Prozessliste)', false];
    }
    return self::proven($pid, $backend, $dir, $start)
      ? [new self($pid, $backend, $dir, $settings), 'lokal (Prozess ' . $pid . ')', false]
      : [new self(null, $backend, $dir, $settings), 'lokal (Serverprozess nicht nachgewiesen — ' . self::UNPROVEN . ')', false];
  }

  /**
   * Linux: $pid is the server only if it is the parent of our own backend, both run as the owner of the data directory (PostgreSQL
   * refuses any other) and it started when the server says it did. The parent alone is not enough: in another PID namespace (server in
   * a container, data directory mounted on the host under the same path) the backend's number names a foreign process of the host,
   * whose parent the service account could copy into postmaster.pid.
   */
  private static function proven(int $pid, int $backend, string $dir, int $start): bool
  {
    $status = Fs::read("/proc/$backend/status", 65536);
    if ($status === null || preg_match('/^PPid:\s+(\d+)$/m', $status, $m) !== 1 || (int) $m[1] !== $pid) {
      return false;
    }
    $owner = Fs::attempt(fn() => stat($dir))['uid'] ?? null;
    if ($owner === null || Fs::attempt(fn() => fileowner("/proc/$pid")) !== $owner || Fs::attempt(fn() => fileowner("/proc/$backend")) !== $owner) {
      return false;
    }
    // Field 22 of /proc/<pid>/stat: start in clock ticks after boot (btime in /proc/stat). The name in field 2 may contain blanks and
    // parentheses, so the fields are counted after the last ")".
    $stat = Fs::read("/proc/$pid/stat", 65536);
    $boot = Fs::read('/proc/stat', 1048576);
    if ($stat === null || $boot === null || preg_match('/^btime\s+(\d+)$/m', $boot, $b) !== 1) {
      return false;
    }
    $fields = preg_split('/\s+/', trim(substr($stat, (int) strrpos($stat, ')') + 1)));
    $ticks = function_exists('posix_sysconf') && defined('POSIX_SC_CLK_TCK') ? (int) posix_sysconf(POSIX_SC_CLK_TCK) : 100;
    if (!isset($fields[19]) || $ticks <= 0) {
      return false;
    }
    // 3 s: btime, the tick division and the server's start time each lose fractions of a second.
    return abs((int) $b[1] + intdiv((int) $fields[19], $ticks) - $start) <= 3;
  }
}

/** Facts that only Windows PowerShell can read; fetched once per run. */
final class WindowsFacts
{
  private static ?array $cache = null;

  public static function get(LocalServer $s): array
  {
    if (self::$cache !== null) {
      return self::$cache;
    }
    $paths = array_values(array_unique(array_filter([
      $s->dataDir, $s->path('config_file'), $s->path('hba_file'), $s->path('ident_file'), $s->dataDir . '/postgresql.auto.conf',
      $s->setting('ssl') === 'on' ? $s->path('ssl_key_file') : null,
      $s->setting('logging_collector') === 'on' ? $s->path('log_directory') : null,
    ])));
    $script = <<<'PS'
      $res = @{ service = $null; signature = $null; acls = @() }
      try {
        # The process number comes from postmaster.pid (a file of the service account): it counts only as the parent of our own backend.
        $b = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$d.backend)
        if (-not $b -or [int]$b.ParentProcessId -ne [int]$d.pid) {
          throw 'Serverprozess nicht nachgewiesen (die Prozessnummer aus postmaster.pid ist nicht der Elternprozess der eigenen Verbindung)'
        }
        $p = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$d.pid)
        # The Windows service is often the parent (pg_ctl runservice starts the postmaster): walk up a few levels.
        $chain = @([int]$d.pid)
        $cur = $p
        for ($i = 0; $i -lt 4 -and $cur -and $cur.ParentProcessId; $i++) {
          $chain += [int]$cur.ParentProcessId
          $cur = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$cur.ParentProcessId)
        }
        $svc = Get-CimInstance Win32_Service | Where-Object { $chain -contains [int]$_.ProcessId } | Select-Object -First 1
        $exe = $null
        if ($p -and $p.ExecutablePath) { $exe = $p.ExecutablePath }
        elseif ($svc -and $svc.PathName -match '^"([^"]+)"') { $exe = $Matches[1] }
        $res.service = @{ name = if ($svc) { [string]$svc.Name } else { $null }; account = if ($svc) { [string]$svc.StartName } else { $null }; exe = $exe }
        if ($exe) {
          $sig = Get-AuthenticodeSignature -LiteralPath $exe
          $res.signature = @{ status = [string]$sig.Status; subject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { $null } }
        }
      } catch { $res.service = @{ error = $_.Exception.Message } }
      foreach ($path in @($d.paths)) {
        try {
          $acl = Get-Acl -LiteralPath $path
          $aces = @()
          foreach ($a in $acl.Access) {
            $sid = ''
            try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
            $aces += @{ sid = $sid; name = [string]$a.IdentityReference.Value; rights = [string]$a.FileSystemRights; type = [string]$a.AccessControlType; inherited = [bool]$a.IsInherited }
          }
          $res.acls += @{ path = $path; aces = $aces }
        } catch { $res.acls += @{ path = $path; error = $_.Exception.Message } }
      }
      ConvertTo-Json -InputObject $res -Depth 6 -Compress
      PS;
    return self::$cache = Platform::powershell($script, ['pid' => $s->pid, 'backend' => $s->backendPid, 'paths' => $paths]);
  }

  /**
   * Owner and every principal with an Allow entry on one path; null if the ACL cannot be read.
   * Unresolvable SIDs come back as '' so that the caller can refuse them.
   *
   * @return ?array{owner: string, sids: string[]}
   */
  public static function strictAcl(string $path): ?array
  {
    $res = Platform::powershell(<<<'PS'
      try {
        $acl = Get-Acl -LiteralPath $d.path
        $owner = ''
        try { $owner = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
        $sids = @()
        foreach ($a in $acl.Access) {
          if ([string]$a.AccessControlType -eq 'Allow') {
            $sid = ''
            try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
            $sids += $sid
          }
        }
        ConvertTo-Json -InputObject @{ ok = $true; owner = $owner; sids = @($sids) } -Compress
      } catch { ConvertTo-Json -InputObject @{ ok = $false } -Compress }
      PS, ['path' => $path]);
    return ($res['ok'] ?? false) === true ? ['owner' => (string) ($res['owner'] ?? ''), 'sids' => array_map('strval', (array) ($res['sids'] ?? []))] : null;
  }

  /** Allow-ACEs of one path for broad principals (Everyone, Users, …); null if the ACL cannot be read. @return ?string[] */
  public static function broadAcesOf(string $path): ?array
  {
    $res = Platform::powershell(<<<'PS'
      $out = @()
      try {
        foreach ($a in (Get-Acl -LiteralPath $d.path).Access) {
          $sid = ''
          try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
          $out += @{ sid = $sid; name = [string]$a.IdentityReference.Value; type = [string]$a.AccessControlType }
        }
        ConvertTo-Json -InputObject @{ ok = $true; aces = $out } -Depth 4 -Compress
      } catch { ConvertTo-Json -InputObject @{ ok = $false } -Compress }
      PS, ['path' => $path]);
    if (($res['ok'] ?? false) !== true) {
      return null;
    }
    return OsProbes::broadNames($res['aces'] ?? []);
  }

  /** @return ?array the ACEs of a path, null if not readable */
  public static function aces(LocalServer $s, string $path): ?array
  {
    foreach (self::get($s)['acls'] ?? [] as $acl) {
      if (($acl['path'] ?? null) === $path) {
        return isset($acl['error']) ? null : ($acl['aces'] ?? []);
      }
    }
    return null;
  }
}

final class OsProbes
{
  public const NAMES = [
    'pgdata_permissions', 'config_permissions', 'ssl_key_permissions', 'log_permissions', 'socket_permissions',
    'umask', 'service_account', 'service_unit', 'log_own_volume', 'disk_free', 'package_source',
  ];

  /** Principals that must never appear in the ACL of server files (SIDs are locale-independent). */
  private const BROAD_SIDS = ['S-1-1-0' => 'Jeder', 'S-1-5-32-545' => 'Benutzer', 'S-1-5-11' => 'Authentifizierte Benutzer', 'S-1-5-4' => 'Interaktiv', 'S-1-5-2' => 'Netzwerk', 'S-1-5-32-546' => 'Gäste', 'S-1-5-7' => 'Anonymer Zugriff'];
  private const DOMAIN_USERS = '/^S-1-5-21-\d+-\d+-\d+-513$/';

  /** @return string[] names of broad principals (Everyone, Users, …) with an Allow entry */
  public static function broadNames(array $aces): array
  {
    $out = [];
    foreach ($aces as $ace) {
      $sid = (string) ($ace['sid'] ?? '');
      $label = self::BROAD_SIDS[$sid] ?? (preg_match(self::DOMAIN_USERS, $sid) === 1 ? 'Domänenbenutzer' : null);
      if ($label !== null && ($ace['type'] ?? '') === 'Allow') {
        $out[] = $label;
      }
    }
    return array_values(array_unique($out));
  }

  /**
   * @return array{findings: array[], unchecked: string[], notes: string[]}
   */
  public static function run(string $probe, LocalServer $s): array
  {
    $r = ['findings' => [], 'unchecked' => [], 'notes' => []];
    match ($probe) {
      'pgdata_permissions' => self::pgdata($s, $r),
      'config_permissions' => self::config($s, $r),
      'ssl_key_permissions' => self::sslKey($s, $r),
      'log_permissions' => self::logs($s, $r),
      'socket_permissions' => self::sockets($s, $r),
      'umask' => self::umask($s, $r),
      'service_account' => self::serviceAccount($s, $r),
      'service_unit' => self::serviceUnit($s, $r),
      'log_own_volume' => self::logVolume($s, $r),
      'disk_free' => self::diskFree($s, $r),
      'package_source' => self::packageSource($s, $r),
    };
    return $r;
  }

  private static function finding(array &$r, string $object, string $detail): void
  {
    $r['findings'][] = ['database' => null, 'object' => $object, 'detail' => $detail, 'fix_sql' => null, 'rollback_sql' => null];
  }

  private static function owner(int $uid): string
  {
    $info = function_exists('posix_getpwuid') ? posix_getpwuid($uid) : false;
    return is_array($info) ? $info['name'] : (string) $uid;
  }

  private static function mode(int $perms): string
  {
    return sprintf('%04o', $perms & 07777);
  }

  /** Windows: ACEs granted to everybody-like principals. */
  private static function broadAces(LocalServer $s, string $path, array &$r, bool $writeOnly = false): void
  {
    $aces = WindowsFacts::aces($s, $path);
    if ($aces === null) {
      $r['unchecked'][] = Text::printable($path) . ': ACL nicht lesbar';
      return;
    }
    foreach ($aces as $ace) {
      $sid = (string) ($ace['sid'] ?? '');
      $label = self::BROAD_SIDS[$sid] ?? (preg_match(self::DOMAIN_USERS, $sid) === 1 ? 'Domänenbenutzer' : null);
      $rights = (string) ($ace['rights'] ?? '');
      $writes = preg_match('/Write|Modify|FullControl|Delete|AppendData|CreateFiles|TakeOwnership|ChangePermissions/', $rights) === 1;
      if ($label !== null && ($ace['type'] ?? '') === 'Allow' && $rights !== 'Synchronize' && (!$writeOnly || $writes)) {
        self::finding($r, $path, "{$label} hat Zugriff ({$ace['rights']}" . (($ace['inherited'] ?? false) ? ', geerbt' : '') . ')');
      }
    }
  }

  /** Unix: any access for "others" and write access for the group on a directory or file; returns its stat. */
  private static function unixExposure(string $path, array &$r): ?array
  {
    $st = Fs::attempt(fn() => stat($path));
    if ($st === null) {
      $r['unchecked'][] = Text::printable($path) . ': nicht lesbar';
      return null;
    }
    $mode = $st['mode'] & 07777;
    if (($mode & 0007) !== 0) {
      self::finding($r, $path, 'für alle Benutzer des Systems zugänglich (Modus ' . self::mode($mode) . ')');
    }
    if (($mode & 0020) !== 0) {
      self::finding($r, $path, 'für die Gruppe beschreibbar (Modus ' . self::mode($mode) . ')');
    }
    return $st;
  }

  private static function pgdata(LocalServer $s, array &$r): void
  {
    if (Platform::windows()) {
      self::broadAces($s, $s->dataDir, $r);
      return;
    }
    $st = self::unixExposure($s->dataDir, $r);
    if ($st === null) {
      return;
    }
    if ($st['uid'] === 0) {
      self::finding($r, $s->dataDir, 'gehört root — PostgreSQL läuft nicht als root und das Verzeichnis gehört dem Dienstkonto');
    }
    $top = Fs::entries($s->dataDir);
    if ($top === null) {
      $r['unchecked'][] = Text::printable($s->dataDir) . ': Inhalt nicht lesbar';
    }
    foreach ($top ?? [] as $name) {
      $entry = $s->dataDir . '/' . $name;
      $est = Fs::attempt(fn() => stat($entry));
      if ($est === null) {
        $r['unchecked'][] = Text::printable($entry) . ': nicht lesbar';
        continue;
      }
      if (($est['mode'] & 0027) !== 0) {
        self::finding($r, $entry, 'zu offene Rechte (Modus ' . self::mode($est['mode']) . '; erwartet 0600/0700 bzw. 0640/0750 bei Gruppenzugriff)');
      }
      if ($est['uid'] !== $st['uid']) {
        self::finding($r, $entry, 'gehört ' . self::owner($est['uid']) . ' statt dem Besitzer des Datenverzeichnisses ' . self::owner($st['uid']));
      }
    }
  }

  private static function config(LocalServer $s, array &$r): void
  {
    $files = array_filter([$s->path('config_file'), $s->path('hba_file'), $s->path('ident_file'), $s->dataDir . '/postgresql.auto.conf']);
    foreach (array_unique($files) as $file) {
      if (Fs::attempt(fn() => file_exists($file)) !== true) {
        continue;
      }
      // postgresql.conf and pg_ident.conf are world-readable on packaged installs by design; pg_hba.conf and
      // postgresql.auto.conf (ALTER SYSTEM, may carry connection strings) are not.
      $readIsProblem = in_array(basename($file), ['pg_hba.conf', 'postgresql.auto.conf'], true);
      if (Platform::windows()) {
        self::broadAces($s, $file, $r, writeOnly: !$readIsProblem);
        continue;
      }
      $st = Fs::attempt(fn() => stat($file));
      if ($st === null) {
        $r['unchecked'][] = Text::printable($file) . ': nicht lesbar';
        continue;
      }
      $mode = $st['mode'] & 07777;
      if (($mode & 0022) !== 0) {
        self::finding($r, $file, 'für Gruppe oder andere beschreibbar (Modus ' . self::mode($mode) . ') — wer schreiben darf, ändert die Zugangsregeln bzw. Einstellungen');
      } elseif ($readIsProblem && ($mode & 0004) !== 0) {
        self::finding($r, $file, 'für alle Benutzer des Systems lesbar (Modus ' . self::mode($mode) . ')');
      }
    }
  }

  private static function sslKey(LocalServer $s, array &$r): void
  {
    $key = $s->path('ssl_key_file');
    if ($s->setting('ssl') !== 'on' || $key === null) {
      $r['notes'][] = 'TLS ist nicht eingeschaltet — nichts zu prüfen';
      return;
    }
    if (Fs::attempt(fn() => file_exists($key)) !== true) {
      $r['unchecked'][] = Text::printable($key) . ': nicht gefunden oder nicht lesbar';
      return;
    }
    if (Platform::windows()) {
      self::broadAces($s, $key, $r);
      return;
    }
    $st = Fs::attempt(fn() => stat($key));
    if ($st === null) {
      $r['unchecked'][] = Text::printable($key) . ': nicht lesbar';
      return;
    }
    $mode = $st['mode'] & 07777;
    // PostgreSQL's own rule: 0600 for the service account, or 0640 if root owns the file.
    $limit = $st['uid'] === 0 ? 0037 : 0077;
    if (($mode & $limit) !== 0) {
      self::finding($r, $key, 'privater Schlüssel zu offen (Modus ' . self::mode($mode) . '; erlaubt 0600' . ($st['uid'] === 0 ? ' oder 0640' : '') . ')');
    }
  }

  private static function logs(LocalServer $s, array &$r): void
  {
    $dir = $s->path('log_directory');
    if ($s->setting('logging_collector') !== 'on' || $dir === null) {
      $r['notes'][] = 'Der Logging-Collector ist aus — Protokolle gehen an syslog/journald oder stderr des Dienstes';
      return;
    }
    if (Platform::windows()) {
      self::broadAces($s, $dir, $r);
      return;
    }
    if (self::unixExposure($dir, $r) === null) {
      return;
    }
    $names = Fs::entries($dir);
    if ($names === null) {
      $r['unchecked'][] = Text::printable($dir) . ': Inhalt nicht lesbar';
      $names = [];
    }
    rsort($names);
    if (count($names) > 1000) {
      $r['unchecked'][] = Text::printable($dir) . ': nur die neuesten 1000 von ' . count($names) . ' Einträgen geprüft';
    }
    foreach (array_slice($names, 0, 1000) as $name) {
      $st = Fs::attempt(fn() => stat($dir . '/' . $name));
      if ($st !== null && ($st['mode'] & 0004) !== 0 && ($st['mode'] & 0040000) === 0) {
        self::finding($r, $dir . '/' . $name, 'Protokolldatei für alle Benutzer lesbar (Modus ' . self::mode($st['mode']) . ')');
      }
    }
  }

  private static function sockets(LocalServer $s, array &$r): void
  {
    $dirs = array_filter(array_map(fn($d) => trim($d, " \t\"'"), explode(',', $s->setting('unix_socket_directories'))));
    if ($dirs === []) {
      $r['notes'][] = 'Kein Unix-Socket konfiguriert';
      return;
    }
    foreach ($dirs as $dir) {
      $dir = Fs::isAbsolute($dir) ? $dir : $s->dataDir . '/' . $dir;
      $st = Fs::attempt(fn() => stat($dir));
      if ($st === null) {
        $r['unchecked'][] = Text::printable($dir) . ': nicht lesbar';
        continue;
      }
      if (($st['mode'] & 0002) !== 0) {
        self::finding($r, $dir, 'Socket-Verzeichnis ist für alle Benutzer beschreibbar (Modus ' . self::mode($st['mode']) . ') — ein anderer Benutzer kann dort einen Socket unterschieben');
      }
    }
    $perm = $s->setting('unix_socket_permissions');
    $permBits = Fs::mode($perm);
    if ($perm !== '' && $permBits === null) {
      $r['unchecked'][] = 'unix_socket_permissions hat eine unerwartete Darstellung';
    } elseif ($permBits !== null && ($permBits & 0007) !== 0) {
      self::finding($r, 'unix_socket_permissions', "ist $perm — jeder Benutzer des Systems kann den Socket erreichen; die Anmeldung schützt dann allein pg_hba.conf (peer)");
    }
  }

  /** The proven server process; null with an "unchecked" line naming what stays unchecked. */
  private static function pid(LocalServer $s, array &$r, string $what): ?int
  {
    if ($s->pid === null) {
      $r['unchecked'][] = $what . ': Serverprozess nicht nachgewiesen (' . LocalServer::UNPROVEN . ')';
    }
    return $s->pid;
  }

  private static function umask(LocalServer $s, array &$r): void
  {
    if (($pid = self::pid($s, $r, 'umask des Serverprozesses')) === null) {
      return;
    }
    $status = Fs::read("/proc/$pid/status", 65536);
    if ($status === null || preg_match('/^Umask:\s+([0-7]+)/m', $status, $m) !== 1) {
      $r['unchecked'][] = 'umask des Serverprozesses nicht lesbar (/proc/' . $pid . '/status)';
      return;
    }
    if ((intval($m[1], 8) & 0007) !== 0007) {
      self::finding($r, 'umask des Serverprozesses', "ist {$m[1]} — neue Dateien (Protokolle, Dumps, Archiv) wären für alle lesbar; erwartet 0077 oder 0027");
    }
  }

  private static function serviceAccount(LocalServer $s, array &$r): void
  {
    if (Platform::windows()) {
      $svc = WindowsFacts::get($s)['service'] ?? null;
      $account = is_array($svc) ? (string) ($svc['account'] ?? '') : '';
      if ($account === '') {
        $r['unchecked'][] = 'Dienstkonto nicht ermittelbar' . (is_array($svc) && isset($svc['error']) ? ': ' . $svc['error'] : '');
        return;
      }
      $r['notes'][] = 'Dienstkonto: ' . $account;
      if (in_array(strtolower($account), ['localsystem', 'nt authority\\system'], true) || str_ends_with(strtolower($account), '\\administrator')) {
        self::finding($r, $account, 'Der Dienst läuft mit einem Konto mit Administratorrechten — ein dediziertes Dienstkonto ohne Anmeldung nutzen (z. B. NT AUTHORITY\\NetworkService oder ein virtuelles Konto)');
      }
      return;
    }
    if (($pid = self::pid($s, $r, 'Dienstkonto')) === null) {
      return;
    }
    $uid = Fs::attempt(fn() => fileowner("/proc/$pid"));
    if ($uid === null) {
      $r['unchecked'][] = 'Besitzer des Serverprozesses nicht ermittelbar';
      return;
    }
    $r['notes'][] = 'Dienstkonto: ' . self::owner($uid);
    if ($uid === 0) {
      self::finding($r, 'root', 'Der Serverprozess läuft als root — ein dediziertes Konto ohne Anmeldeshell verwenden');
    }
  }

  private static function serviceUnit(LocalServer $s, array &$r): void
  {
    if (($pid = self::pid($s, $r, 'Umgebung und Dienstdatei')) === null) {
      return;
    }
    $cgroup = Fs::read("/proc/$pid/cgroup", 65536);
    $environ = Fs::read("/proc/$pid/environ", 1048576);
    if ($environ === null) {
      $r['unchecked'][] = 'Umgebung des Serverprozesses nicht lesbar (/proc/' . $pid . '/environ — root bzw. Dienstkonto nötig)';
    }
    if ($environ !== null) {
      foreach (explode("\0", $environ) as $var) {
        $name = strtok($var, '=');
        if (is_string($name) && preg_match('/^(PGPASSWORD|PGPASSFILE_CONTENT|.*PASSWORD.*)$/i', $name) === 1) {
          self::finding($r, "/proc/$pid/environ", "Umgebung des Serverprozesses enthält $name (Wert wird nicht ausgegeben)");
        }
      }
    }
    if ($cgroup === null || preg_match('~/([A-Za-z0-9@:._\\\\-]+\.service)\s*$~m', $cgroup, $m) !== 1) {
      $r['notes'][] = 'Kein systemd-Dienst ermittelt — Dienstdatei nicht geprüft';
      return;
    }
    $unit = $m[1];
    $names = [$unit];
    if (preg_match('/^([^@]+@)[^.]*(\.service)$/', $unit, $t) === 1) {
      $names[] = $t[1] . $t[2];
    }
    $found = false;
    foreach (['/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'] as $base) {
      foreach ($names as $name) {
        $files = [$base . '/' . $name];
        foreach (Fs::entries($base . '/' . $name . '.d') ?? [] as $drop) {
          $files[] = $base . '/' . $name . '.d/' . $drop;
        }
        foreach ($files as $file) {
          if (Fs::attempt(fn() => is_file($file)) === true) {
            $found = true;
            self::unitFile($file, $r);
          }
        }
      }
    }
    if (!$found) {
      $r['notes'][] = 'Dienstdatei von ' . Text::printable($unit) . ' nicht gefunden';
    }
  }

  private static function unitFile(string $file, array &$r): void
  {
    $st = Fs::attempt(fn() => stat($file));
    if ($st !== null && ($st['mode'] & 0022) !== 0) {
      self::finding($r, $file, 'Dienstdatei ist für Gruppe oder andere beschreibbar (Modus ' . self::mode($st['mode']) . ')');
    }
    $content = Fs::readGuarded($file, 1048576);
    if ($content === null) {
      $r['unchecked'][] = Text::printable($file) . ': nicht lesbar';
      return;
    }
    foreach (preg_split('/\r\n|\n|\r/', $content) as $i => $line) {
      $n = $i + 1;
      if (preg_match('/^\s*Environment(File)?\s*=\s*(.*)$/i', $line, $m) === 1) {
        if ($m[1] === '' && preg_match('/\b(\w*PASSWORD\w*|\w*PASSWD\w*|\w*SECRET\w*)\s*=/i', $m[2], $k) === 1) {
          self::finding($r, "$file:$n", "Environment enthält {$k[1]} im Klartext (Wert wird nicht ausgegeben)");
        }
        if ($m[1] !== '') {
          $target = ltrim(trim($m[2]), '-');
          $tst = Fs::attempt(fn() => stat($target));
          if ($tst !== null && ($tst['mode'] & 0004) !== 0) {
            self::finding($r, "$file:$n", 'EnvironmentFile ' . Text::printable($target) . ' ist für alle Benutzer lesbar (Modus ' . self::mode($tst['mode']) . ')');
          }
        }
      }
      if (preg_match('/^\s*User\s*=\s*root\s*$/i', $line) === 1) {
        self::finding($r, "$file:$n", 'Dienst ist auf User=root eingestellt');
      }
    }
  }

  /** @return array<string, array{path: string, dev: int}> */
  private static function volumes(LocalServer $s): array
  {
    $out = [];
    $add = function (string $role, ?string $path) use (&$out): void {
      $st = $path === null ? null : Fs::attempt(fn() => stat($path));
      if ($st !== null) {
        $out[$role] = ['path' => $path, 'dev' => $st['dev']];
      }
    };
    $add('Datenverzeichnis', $s->dataDir);
    $add('WAL (pg_wal)', $s->dataDir . '/pg_wal');
    if ($s->setting('logging_collector') === 'on') {
      $add('Protokolle', $s->path('log_directory'));
    }
    return $out;
  }

  private static function logVolume(LocalServer $s, array &$r): void
  {
    if ($s->setting('logging_collector') !== 'on') {
      $r['notes'][] = 'Der Logging-Collector ist aus — kein Log-Verzeichnis';
      return;
    }
    $v = self::volumes($s);
    if (!isset($v['Protokolle'])) {
      $r['unchecked'][] = 'Log-Verzeichnis nicht lesbar';
      return;
    }
    foreach (['Datenverzeichnis', 'WAL (pg_wal)'] as $other) {
      if (isset($v[$other]) && $v[$other]['dev'] === $v['Protokolle']['dev']) {
        self::finding($r, $v['Protokolle']['path'], "liegt auf demselben Datenträger wie das $other — volle Protokolle (Log-Flooding) verdrängen dort Daten bzw. WAL");
      }
    }
  }

  private static function diskFree(LocalServer $s, array &$r): void
  {
    $seen = [];
    foreach (self::volumes($s) as $role => $v) {
      if (isset($seen[$v['dev']])) {
        continue;
      }
      $seen[$v['dev']] = true;
      $free = Fs::attempt(fn() => disk_free_space($v['path']));
      $total = Fs::attempt(fn() => disk_total_space($v['path']));
      if ($free === null || $total === null || $total <= 0) {
        $r['unchecked'][] = "$role: Speicherplatz nicht ermittelbar";
        continue;
      }
      $pct = $free / $total * 100;
      $r['notes'][] = sprintf('%s: %.0f %% frei (%.1f GiB)', $role, $pct, $free / 1073741824);
      if ($pct < 15.0) {
        self::finding($r, $v['path'], sprintf('nur %.0f %% frei (%.1f GiB) — ein voller Datenträger stoppt den Server', $pct, $free / 1073741824));
      }
    }
  }

  private static function packageSource(LocalServer $s, array &$r): void
  {
    if (Platform::windows()) {
      $facts = WindowsFacts::get($s);
      $sig = $facts['signature'] ?? null;
      if (!is_array($sig)) {
        $r['unchecked'][] = 'Programmdatei des Dienstes nicht ermittelbar';
        return;
      }
      $r['notes'][] = 'Signatur: ' . $sig['status'] . (($sig['subject'] ?? null) !== null ? ' (' . $sig['subject'] . ')' : '');
      // Many vendor installers ship unsigned binaries (NotSigned): that is a note, not a finding.
      // A signature that does not verify means the file was changed or the chain is untrusted.
      if (in_array($sig['status'], ['HashMismatch', 'NotTrusted', 'UnknownError', 'Incompatible'], true)) {
        self::finding($r, (string) ($facts['service']['exe'] ?? 'Programmdatei'), 'Signatur der Programmdatei ist ungültig (' . $sig['status'] . ') — Datei wurde verändert oder stammt nicht vom Hersteller; Herkunft klären, Installer des Herstellers verwenden');
      }
      return;
    }
    if (($pid = self::pid($s, $r, 'Paketherkunft')) === null) {
      return;
    }
    $exe = Fs::attempt(fn() => readlink("/proc/$pid/exe"));
    if ($exe === null) {
      $r['unchecked'][] = 'Programmdatei des Serverprozesses nicht ermittelbar (/proc/' . $pid . '/exe — root nötig)';
      return;
    }
    $exe = preg_replace('/ \(deleted\)$/', '', $exe);
    foreach ([['dpkg', ['-S']], ['rpm', ['-qf']], ['apk', ['info', '-W']]] as [$tool, $args]) {
      $bin = Platform::unixTool($tool);
      if ($bin === null) {
        continue;
      }
      [$code, $out] = Platform::run(array_merge([$bin], $args, [$exe]));
      if ($code === 0 && trim($out) !== '') {
        $r['notes'][] = 'Paketverwaltung ' . $tool . ': ' . Text::printable(strtok(trim($out), "\n"));
        return;
      }
      self::finding($r, $exe, "gehört keinem Paket der Paketverwaltung ($tool) — selbst gebaut oder entpackt: Sicherheitsupdates kommen nicht automatisch");
      return;
    }
    $r['unchecked'][] = 'Keine bekannte Paketverwaltung (dpkg, rpm, apk) gefunden';
  }
}
