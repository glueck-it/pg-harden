<?php
declare(strict_types=1);

/**
 * `pg-harden apply` / `rollback`: the only parts of the tool that write.
 *
 * Safety model (in this order):
 *  1. Nothing happens without --execute; the default is a dry run that lists every action.
 *  2. Only rules with automation "auto" run; "confirm" rules need their id in --include-confirm.
 *  3. Every file is backed up into a new journal directory first; the journal also records the rollback SQL.
 *  4. pg_hba.conf and the include file are validated from the server's point of view (pg_hba_file_rules,
 *     pg_file_settings) BEFORE the reload; any error restores the backups without reloading.
 *  5. After the reload a NEW connection must still work (already open sessions survive a bad pg_hba.conf and
 *     would hide a lockout); if it does not, the backups are restored and the configuration is reloaded again.
 *  6. "local" lines of pg_hba.conf are never changed, so the Unix-socket access of the operating system user
 *     stays. Parameters that need a restart are written but reported — the tool never restarts the server.
 *
 * MIT License, Copyright (c) 2026 Frank Glück (Glück IT) — see LICENSE. Provided "as is", without warranty.
 */

/** Token-exact edits of single pg_hba.conf lines: only the field that is meant to change, comments and spacing stay. */
final class HbaFile
{
  /** @return array<int, array{0: int, 1: int}> start (inclusive) and end (exclusive) byte offsets of every token before a comment */
  public static function tokens(string $line): array
  {
    $out = [];
    $n = strlen($line);
    $i = 0;
    while ($i < $n) {
      while ($i < $n && ctype_space($line[$i])) {
        $i++;
      }
      if ($i >= $n || $line[$i] === '#') {
        break;
      }
      $start = $i;
      $quoted = false;
      while ($i < $n) {
        $ch = $line[$i];
        if ($ch === '"') {
          $quoted = !$quoted;
        } elseif (!$quoted && ($ch === '#' || ctype_space($ch))) {
          break;
        }
        $i++;
      }
      $out[] = [$start, $i];
    }
    return $out;
  }

  /** A trailing backslash continues the rule on the next line — such rules are not edited. */
  public static function continues(string $line): bool
  {
    return preg_match('/\\\\\s*$/', $line) === 1;
  }

  /** Index of the authentication method token for a parsed row, or null if the line does not look as expected. */
  public static function methodIndex(string $line, string $type): ?int
  {
    $t = self::tokens($line);
    if ($type === 'local') {
      return count($t) > 3 ? 3 : null;
    }
    if (count($t) < 5) {
      return null;
    }
    $address = substr($line, $t[3][0], $t[3][1] - $t[3][0]);
    // An IP address without /prefix is followed by a separate netmask token.
    $separateMask = !str_contains($address, '/') && filter_var($address, FILTER_VALIDATE_IP) !== false;
    $idx = $separateMask ? 5 : 4;
    return count($t) > $idx ? $idx : null;
  }

  /** @param string[] $expected the token must be exactly one of these (unquoted) */
  public static function replaceToken(string $line, int $index, array $expected, string $new): ?string
  {
    $t = self::tokens($line);
    if (!isset($t[$index])) {
      return null;
    }
    [$start, $end] = $t[$index];
    if (!in_array(substr($line, $start, $end - $start), $expected, true)) {
      return null;
    }
    return substr($line, 0, $start) . $new . substr($line, $end);
  }
}

/** Journal directory: backups, what was done, what undoes it. Rewritten (atomically) after every step so a crash leaves a trace. */
final class Journal
{
  public const VERSION = 1;
  public array $data;

  public function __construct(public readonly string $dir, array $header)
  {
    Files::prepareDir($dir);
    self::lockDown($dir);
    if (Fs::attempt(fn() => mkdir($dir . '/backup', 0700)) !== true) {
      throw new HardenException("Verzeichnis $dir/backup lässt sich nicht anlegen.");
    }
    $this->data = $header + ['journal_version' => self::VERSION, 'steps' => [], 'files' => [], 'sql' => []];
    $this->flush();
  }

  /** Only this user, SYSTEM and Administrators may touch the journal: it later drives writes with elevated rights. */
  private static function lockDown(string $dir): void
  {
    if (!Platform::windows()) {
      Fs::attempt(fn() => chmod($dir, 0700));
      return;
    }
    $args = [Platform::systemTool('icacls.exe'), $dir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '/grant:r', '*S-1-5-32-544:(OI)(CI)F'];
    if (($sid = Platform::currentSid()) !== null) {
      array_push($args, '/grant:r', "*$sid:(OI)(CI)F");
    }
    if (Platform::run($args)[0] !== 0) {
      throw new HardenException('Das Journal-Verzeichnis lässt sich nicht schützen (icacls) — nichts geändert.');
    }
  }

  /** The journal drives writes with elevated rights: it is only trusted if nobody else could have touched it. */
  public static function load(string $dir): array
  {
    if (!Platform::windows() && function_exists('posix_geteuid')) {
      $st = Fs::attempt(fn() => stat($dir));
      if ($st === null || $st['uid'] !== posix_geteuid() || ($st['mode'] & 0077) !== 0) {
        throw new HardenException("$dir gehört nicht dem ausführenden Benutzer oder ist für andere zugänglich — dem Journal wird nicht vertraut.");
      }
    }
    if (Platform::windows()) {
      $broad = WindowsFacts::broadAcesOf($dir);
      if ($broad === null || $broad !== []) {
        throw new HardenException("$dir ist für andere Konten zugänglich oder die ACL ist nicht lesbar — dem Journal wird nicht vertraut.");
      }
    }
    $data = Fs::attempt(fn() => json_decode((string) file_get_contents($dir . '/apply-log.json'), true));
    if (!is_array($data) || ($data['journal_version'] ?? null) !== self::VERSION || !is_array($data['files'] ?? null) || !is_array($data['sql'] ?? null)) {
      throw new HardenException("$dir enthält kein Journal von apply (apply-log.json, Version " . self::VERSION . ').');
    }
    foreach ($data['files'] as $f) {
      $ok = is_array($f) && is_string($f['path'] ?? null) && !Text::hasControl($f['path']) && in_array($f['action'] ?? null, ['modified', 'created'], true)
        && (($f['action'] ?? '') === 'created' ? ($f['backup'] ?? null) === null
          : (is_string($f['backup'] ?? null) && preg_match('~^backup/\d{2}-[A-Za-z0-9._-]+$~', $f['backup']) === 1));
      if (!$ok) {
        throw new HardenException('Journal enthält einen ungültigen Dateieintrag — abgebrochen.');
      }
    }
    foreach ($data['sql'] as $q) {
      $ok = is_array($q) && is_string($q['database'] ?? null) && is_string($q['rule'] ?? null) && in_array($q['status'] ?? null, ['pending', 'committed', 'failed'], true);
      if (!$ok) {
        throw new HardenException('Journal enthält einen ungültigen SQL-Eintrag — abgebrochen.');
      }
    }
    return $data;
  }

  /** @return ?string relative path of the copy, null if the file did not exist */
  public function backup(string $path): ?string
  {
    // Read with the identity of the file's owner: a symlink planted by the service account leads nowhere new.
    $exists = Fs::asOwnerOf($path, fn() => Fs::attempt(fn() => is_file($path)));
    if ($exists !== true) {
      return null;
    }
    $content = Fs::asOwnerOf($path, fn() => Fs::attempt(fn() => file_get_contents($path)));
    $name = sprintf('backup/%02d-%s', count($this->data['files']) + 1, preg_replace('/[^A-Za-z0-9._-]/', '_', basename($path)));
    $fh = $content === null ? null : Fs::attempt(fn() => fopen($this->dir . '/' . $name, 'x'));
    if (!is_resource($fh) || fwrite($fh, $content) !== strlen($content) || !fclose($fh)) {
      throw new HardenException('Sicherung von ' . Text::printable($path) . ' fehlgeschlagen — nichts wurde geändert.');
    }
    Fs::attempt(fn() => chmod($this->dir . '/' . $name, 0600));
    return $name;
  }

  public function file(string $path, string $action, ?string $backup): void
  {
    $this->data['files'][] = ['path' => $path, 'action' => $action, 'backup' => $backup];
    $this->flush();
  }

  /** The last file entry describes an action that failed before it changed anything. */
  public function forgetLast(): void
  {
    array_pop($this->data['files']);
    $this->flush();
  }

  public function step(string $phase, string $status, string $message): void
  {
    $this->data['steps'][] = ['at' => date(DATE_ATOM), 'phase' => $phase, 'status' => $status, 'message' => $message];
    $this->flush();
  }

  /** Written BEFORE the statement is committed (status "pending"): a crash between COMMIT and journal must not lose the way back. */
  public function sql(string $database, string $rule, string $fix, ?string $rollback): int
  {
    $this->data['sql'][] = ['database' => $database, 'rule' => $rule, 'fix_sql' => $fix, 'rollback_sql' => $rollback, 'status' => 'pending'];
    $index = array_key_last($this->data['sql']);
    try {
      $this->flush();
    } catch (Throwable $e) {
      array_pop($this->data['sql']);
      throw $e;
    }
    return $index;
  }

  public function markSql(int $index, string $status): void
  {
    $this->data['sql'][$index]['status'] = $status;
    $this->flush();
  }

  public function flush(): void
  {
    $tmp = $this->dir . '/.apply-log.tmp';
    Files::write($tmp, Text::json($this->data));
    if (Fs::attempt(fn() => rename($tmp, $this->dir . '/apply-log.json')) !== true) {
      throw new HardenException('Journal lässt sich nicht schreiben.');
    }
  }
}

/** Restores the backups if the process dies while pg_hba.conf/postgresql.conf are in flux (fatal error, Ctrl+C, kill). */
final class Guard
{
  private static ?array $active = null;
  private static bool $registered = false;

  public static function arm(Journal $journal, ServerFiles $files): void
  {
    self::$active = ['journal' => $journal, 'files' => $files];
    if (self::$registered) {
      return;
    }
    self::$registered = true;
    register_shutdown_function([self::class, 'onShutdown']);
    if (function_exists('pcntl_async_signals') && function_exists('pcntl_signal')) {
      pcntl_async_signals(true);
      foreach ([SIGINT, SIGTERM, SIGHUP] as $signal) {
        pcntl_signal($signal, fn() => exit(130));
      }
    } elseif (function_exists('sapi_windows_set_ctrl_handler')) {
      sapi_windows_set_ctrl_handler(fn() => exit(130));
    }
  }

  public static function disarm(): void
  {
    self::$active = null;
  }

  public static function onShutdown(): void
  {
    if (self::$active === null) {
      return;
    }
    ['journal' => $journal, 'files' => $files] = self::$active;
    self::$active = null;
    // exit() skips finally blocks: a signal inside Fs::asOwnerOf must not leave this process as the service account.
    if (function_exists('posix_seteuid')) {
      posix_seteuid(0);
      posix_setegid(0);
    }
    // A second Ctrl+C must not interrupt the restore.
    if (function_exists('pcntl_signal')) {
      foreach ([SIGINT, SIGTERM, SIGHUP] as $signal) {
        pcntl_signal($signal, SIG_IGN);
      }
    } elseif (function_exists('sapi_windows_set_ctrl_handler')) {
      sapi_windows_set_ctrl_handler(fn() => true);
    }
    try {
      $problems = ServerFiles::restore($journal->data['files'], $journal->dir);
      if ($problems === []) {
        $files->reload();
      }
      try {
        $journal->step('Abbruch', 'FEHLER', 'Lauf unterbrochen — Sicherungen ' . ($problems === [] ? 'zurückgespielt und Konfiguration neu geladen' : 'nur teilweise zurückgespielt: ' . implode(' | ', $problems)));
      } catch (Throwable) {
      }
    } catch (Throwable) {
      // Last resort: nothing more to do than to tell the operator where the backups are.
    }
    try {
      fwrite(STDERR, 'pg-harden: Lauf unterbrochen. Sicherungen und Journal: ' . Text::printable($journal->dir) . "\n");
    } catch (Throwable) {
    }
  }
}

/** Shared server-side checks and file handling for apply and rollback. */
final class ServerFiles
{
  public function __construct(private readonly Connector $connector) {}

  /** @return array<int, array> rows of pg_hba_file_rules, ordered */
  public function hbaRows(): array
  {
    $rows = Connector::readOnly($this->connector->connect(), <<<'SQL'
      SELECT f.line_number
           , f.type
           , f.database
           , f.user_name
           , f.address
           , f.netmask
           , f.auth_method
           , f.options
           , f.error
           , to_jsonb(f) ->> 'file_name' AS file_name
        FROM pg_hba_file_rules f
      SQL);
    usort($rows, fn($a, $b) => [(string) ($a['file_name'] ?? ''), (int) $a['line_number']] <=> [(string) ($b['file_name'] ?? ''), (int) $b['line_number']]);
    return $rows;
  }

  /**
   * Configuration problems the server itself reports for the files on disk. "Could not be applied" on a
   * parameter that needs a restart is not an error — the value simply waits for the next start.
   *
   * @return string[]
   */
  public function configErrors(): array
  {
    $rows = Connector::readOnly($this->connector->connect(), <<<'SQL'
      SELECT f.sourcefile
           , f.sourceline
           , f.name
           , f.error
        FROM pg_file_settings f
        LEFT JOIN pg_settings s ON s.name = f.name
       WHERE f.error IS NOT NULL
         AND NOT (f.error ILIKE '%could not be applied%' AND s.context = 'postmaster')
       ORDER BY f.sourcefile, f.sourceline
      SQL);
    return array_map(fn($r) => basename((string) $r['sourcefile']) . ':' . $r['sourceline'] . ' ' . $r['name'] . ' — ' . $r['error'], $rows);
  }

  public function hbaErrors(): array
  {
    return array_map(fn($r) => 'Zeile ' . $r['line_number'] . ': ' . $r['error'], array_filter($this->hbaRows(), fn($r) => $r['error'] !== null));
  }

  /** @return array{data_directory: string, system_identifier: string} what a journal must match to belong to this cluster */
  public function identity(): array
  {
    $row = Connector::readOnly($this->connector->connect(), <<<'SQL'
      SELECT current_setting('data_directory') AS data_directory
           , (SELECT system_identifier::text FROM pg_control_system()) AS system_identifier
      SQL)[0];
    return ['data_directory' => (string) $row['data_directory'], 'system_identifier' => (string) $row['system_identifier']];
  }

  /** Comparable form of a path that may not exist yet. */
  public static function norm(string $path): ?string
  {
    $c = Fs::canonical($path);
    if ($c !== null) {
      return $c;
    }
    $dir = Fs::canonical(dirname($path));
    return $dir === null ? null : $dir . '/' . (Platform::windows() ? strtolower(basename($path)) : basename($path));
  }

  /** The only paths apply ever writes, and so the only ones a journal may name. @return string[] */
  public static function allowedTargets(LocalServer $local): array
  {
    $out = [];
    foreach (['hba_file', 'config_file'] as $name) {
      $p = $local->path($name);
      $out[] = $p === null ? null : self::norm($p);
    }
    $conf = $local->path('config_file');
    $config = $conf === null ? null : Fs::attempt(fn() => file_get_contents($conf));
    $inc = ($config === null ? null : Applier::includeDir($config, $conf)) ?? ($conf === null ? null : dirname($conf) . '/conf.d');
    if ($inc !== null) {
      $out[] = self::norm($inc);
      $out[] = ($d = self::norm($inc)) === null ? null : $d . '/90-pg-harden.conf';
    }
    return array_values(array_filter($out));
  }

  /** The catalog objects rule db.catalog_visibility may REVOKE/GRANT SELECT on — nothing else in pg_catalog is ever touched. */
  public const CATALOG_NAMES = [
    'pg_database', 'pg_roles', 'pg_user', 'pg_group', 'pg_auth_members',
    'pg_stat_database', 'pg_stat_database_conflicts', 'pg_shdescription',
  ];

  /**
   * SQL that apply and rollback execute: exactly the shapes the rule catalog produces, nothing wider.
   *  - REVOKE/GRANT of CREATE, CONNECT, TEMPORARY or USAGE on ONE schema or database (never pg_catalog, information_schema, pg_toast;
   *    never ALL), from/to PUBLIC;
   *  - REVOKE/GRANT of SELECT on a list of the CATALOG_NAMES in pg_catalog, from/to PUBLIC;
   *  - ALTER ROUTINE/FUNCTION/PROCEDURE schema.name(arguments) SET search_path = list | RESET search_path.
   * The statement length is capped before the pattern runs.
   */
  public static function sqlAllowed(?string $sql): bool
  {
    if ($sql === null || strlen($sql) > 8192 || !Text::isSafeStatement($sql)) {
      return false;
    }
    $id = '(?:[a-z_][a-z0-9_]*|"(?:[^"]|"")+")';
    $priv = '(?:CREATE|CONNECT|TEMPORARY|TEMP|USAGE)(?:\s*,\s*(?:CREATE|CONNECT|TEMPORARY|TEMP|USAGE))*';
    $object = '(?:SCHEMA|DATABASE)\s+(?!"?(?:pg_catalog|information_schema|pg_toast)"?(?:\s|;))' . $id;
    $names = implode('|', self::CATALOG_NAMES);
    $catalog = 'TABLE\s+pg_catalog\.(?:' . $names . ')(?:\s*,\s*pg_catalog\.(?:' . $names . '))*';
    $list = $id . '(?:\s*,\s*' . $id . ')*';
    return preg_match(
      '/^(?:REVOKE\s+' . $priv . '\s+ON\s+' . $object . '\s+FROM\s+PUBLIC;'
      . '|REVOKE\s+SELECT\s+ON\s+' . $catalog . '\s+FROM\s+PUBLIC;'
      . '|GRANT\s+' . $priv . '\s+ON\s+' . $object . '\s+TO\s+PUBLIC;'
      . '|GRANT\s+SELECT\s+ON\s+' . $catalog . '\s+TO\s+PUBLIC;'
      . '|ALTER\s+(?:ROUTINE|FUNCTION|PROCEDURE)\s+(?!"?(?:pg_catalog|information_schema|pg_toast)"?\.)' . $id . '\.' . $id . '\s*\([^()]*\)\s+(?:SET\s+search_path\s*=\s*' . $list . '|RESET\s+search_path);)$/iD',
      $sql,
    ) === 1;
  }

  /**
   * A fix and its way back belong together: both allowed, and the way back undoes exactly this fix — a REVOKE by the GRANT with the same
   * privileges on the same object (names inside quotes compared byte for byte), an ALTER by an ALTER of the same routine.
   * Anything else in a journal (also non-string values) is refused.
   */
  public static function pairAllowed(mixed $fix, mixed $rollback): bool
  {
    if (!is_string($fix) || !is_string($rollback) || !self::sqlAllowed($fix) || !self::sqlAllowed($rollback)) {
      return false;
    }
    $norm = static fn(string $x): string => strtolower(trim((string) preg_replace('/\s+/', ' ', $x)));
    if (preg_match('/^REVOKE\s+(.+?)\s+ON\s+(SCHEMA|DATABASE|TABLE)\s+(.+)\s+FROM\s+PUBLIC;$/is', $fix, $f) === 1) {
      if (preg_match('/^GRANT\s+(.+?)\s+ON\s+(SCHEMA|DATABASE|TABLE)\s+(.+)\s+TO\s+PUBLIC;$/is', $rollback, $r) !== 1) {
        return false;
      }
      $same = strtoupper($f[2]) === 'TABLE' ? $norm($f[3]) === $norm($r[3]) : $f[3] === $r[3];
      return $norm($f[1]) === $norm($r[1]) && strtoupper($f[2]) === strtoupper($r[2]) && $same;
    }
    $routine = '/^ALTER\s+(ROUTINE|FUNCTION|PROCEDURE)\s+([^(]+\([^()]*\))\s/i';
    // The fix always puts pg_temp last (that is what the rule exists for); the way back may RESET or restore an old list.
    return preg_match($routine, $fix, $f) === 1 && preg_match($routine, $rollback, $r) === 1
      && preg_match('/\sSET\s+search_path\s*=.*,\s*"?pg_temp"?;$/is', $fix) === 1
      && strtoupper($f[1]) === strtoupper($r[1]) && $f[2] === $r[2];
  }

  private static function writeAll($fh, string $content): bool
  {
    $len = strlen($content);
    for ($off = 0; $off < $len;) {
      $n = fwrite($fh, substr($content, $off));
      if ($n === false || $n === 0) {
        return false;
      }
      $off += $n;
    }
    return fflush($fh);
  }

  /**
   * Replaces a file without ever leaving it empty or half written. Unix: temp file next to it, mode and group
   * copied, then rename. Where that is impossible (Windows, directory not writable): the new content is written
   * first and the file shortened afterwards. As root, the work happens with the identity of the file's owner.
   */
  public static function overwrite(string $path, string $content): void
  {
    try {
      Fs::asOwnerOf($path, function () use ($path, $content): void {
        if (is_link($path)) {
          throw new HardenException(Text::printable($path) . ' ist ein symbolischer Link — wird nicht überschrieben.');
        }
        $st = stat($path);
        if (!Platform::windows()) {
          $tmp = dirname($path) . '/.pg-harden-' . bin2hex(random_bytes(6)) . '.tmp';
          $fh = Fs::attempt(fn() => fopen($tmp, 'x'));
          if (is_resource($fh)) {
            try {
              $ok = self::writeAll($fh, $content);
              Fs::attempt(fn() => fsync($fh));
              fclose($fh);
              if (!$ok) {
                throw new HardenException('Schreiben von ' . Text::printable($path) . ' fehlgeschlagen (Datenträger voll?).');
              }
              chmod($tmp, $st['mode'] & 07777);
              Fs::attempt(fn() => chgrp($tmp, $st['gid']));
              // A file mounted on its own (container bind mount) cannot be replaced: fall back to writing in place.
              if (Fs::attempt(fn() => rename($tmp, $path)) === true) {
                return;
              }
            } finally {
              Fs::attempt(fn() => file_exists($tmp) && unlink($tmp));
            }
          }
        }
        $fh = Fs::attempt(fn() => fopen($path, 'r+'));
        if (!is_resource($fh)) {
          throw new HardenException('Keine Schreibrechte auf ' . Text::printable($path) . ' — als Dienstkonto bzw. mit Administrator-/root-Rechten ausführen.');
        }
        $ok = flock($fh, LOCK_EX) && rewind($fh) && self::writeAll($fh, $content) && ftruncate($fh, strlen($content)) && fflush($fh);
        Fs::attempt(fn() => fsync($fh));
        flock($fh, LOCK_UN);
        fclose($fh);
        if (!$ok) {
          throw new HardenException('Schreiben von ' . Text::printable($path) . ' fehlgeschlagen — Sicherung zurückspielen.');
        }
      });
    } catch (ErrorException $e) {
      throw new HardenException('Schreiben von ' . Text::printable($path) . ' fehlgeschlagen: ' . $e->getMessage());
    }
  }

  /** New directory with the owner and group of its parent (as root a plain mkdir would lock the server out of it). */
  public static function makeDir(string $dir, string $parent): void
  {
    try {
      Fs::asOwnerOf($dir, function () use ($dir, $parent): void {
        if (Fs::attempt(fn() => mkdir($dir, 0750)) !== true) {
          throw new HardenException('Verzeichnis ' . Text::printable($dir) . ' lässt sich nicht anlegen.');
        }
        $st = Fs::attempt(fn() => stat($parent));
        if ($st !== null && !Platform::windows() && function_exists('posix_geteuid') && posix_geteuid() === 0) {
          Fs::attempt(fn() => chown($dir, $st['uid']));
          Fs::attempt(fn() => chgrp($dir, $st['gid']));
        }
      });
    } catch (ErrorException $e) {
      throw new HardenException('Verzeichnis ' . Text::printable($dir) . ' lässt sich nicht anlegen: ' . $e->getMessage());
    }
  }

  public static function assertWritable(string $path): void
  {
    $fh = Fs::asOwnerOf($path, fn() => Fs::attempt(fn() => fopen($path, 'r+')));
    if (!is_resource($fh)) {
      throw new HardenException('Keine Schreibrechte auf ' . Text::printable($path) . ' — als Dienstkonto bzw. mit Administrator-/root-Rechten ausführen.');
    }
    fclose($fh);
  }

  /** New file next to an existing sibling: same mode and (as root) the same owner and group. */
  public static function create(string $path, string $content, string $sibling): void
  {
    try {
      Fs::asOwnerOf($path, function () use ($path, $content, $sibling): void {
        $fh = Fs::attempt(fn() => fopen($path, 'x'));
        if (!is_resource($fh)) {
          throw new HardenException('Datei ' . Text::printable($path) . ' lässt sich nicht anlegen (Rechte oder Verzeichnis fehlt).');
        }
        $ok = self::writeAll($fh, $content);
        fclose($fh);
        $st = Fs::attempt(fn() => stat($sibling));
        if ($st !== null && !Platform::windows()) {
          Fs::attempt(fn() => chmod($path, ($st['mode'] & 0660) ?: 0640));
          if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            Fs::attempt(fn() => chown($path, $st['uid']));
            Fs::attempt(fn() => chgrp($path, $st['gid']));
          }
        }
        if (!$ok) {
          throw new HardenException('Schreiben von ' . Text::printable($path) . ' fehlgeschlagen.');
        }
      });
    } catch (ErrorException $e) {
      throw new HardenException('Datei ' . Text::printable($path) . ' lässt sich nicht anlegen: ' . $e->getMessage());
    }
  }

  /** @return array{0: bool, 1: string} whether the reload was seen within the time limit */
  public function reload(): array
  {
    $pdo = $this->connector->connect();
    $before = (string) Connector::readOnly($pdo, 'SELECT pg_conf_load_time() AS t')[0]['t'];
    $sent = Connector::readOnly($pdo, 'SELECT pg_reload_conf() AS ok')[0]['ok'];
    if (!$sent) {
      return [false, 'pg_reload_conf() meldet Fehler'];
    }
    for ($i = 0; $i < 120; $i++) {
      usleep(250000);
      if ((string) Connector::readOnly($pdo, 'SELECT pg_conf_load_time() AS t')[0]['t'] !== $before) {
        return [true, ''];
      }
    }
    return [false, 'Neuladen nach 30 s nicht bestätigt'];
  }

  /**
   * A NEW login with the same credentials. Open sessions survive a broken pg_hba.conf and prove nothing.
   * It proves only this one identity and route — application roles and clients are not tested.
   *
   * @return array{0: bool, 1: string}
   */
  public function newLoginWorks(): array
  {
    try {
      Connector::readOnly($this->connector->fresh(), 'SELECT 1');
      return [true, ''];
    } catch (Throwable $e) {
      return [false, strtok($e->getMessage(), "\n") ?: 'unbekannt'];
    }
  }

  /** Restores backups (modified files) and removes created files and directories, newest first. @return string[] problems */
  public static function restore(array $files, string $journalDir): array
  {
    $problems = [];
    foreach (array_reverse($files) as $f) {
      try {
        if ($f['action'] === 'created') {
          Fs::asOwnerOf($f['path'], function () use ($f): void {
            if (file_exists($f['path'])) {
              $removed = is_dir($f['path']) ? rmdir($f['path']) : unlink($f['path']);
              if (!$removed) {
                throw new HardenException('Eintrag ' . $f['path'] . ' ließ sich nicht entfernen');
              }
            }
          });
        } else {
          $content = Fs::attempt(fn() => file_get_contents($journalDir . '/' . $f['backup']));
          if ($content === null) {
            $problems[] = 'Sicherung ' . $f['backup'] . ' nicht lesbar';
            continue;
          }
          self::overwrite($f['path'], $content);
        }
      } catch (Throwable $e) {
        $problems[] = strtok($e->getMessage(), "\n") ?: get_class($e);
      }
    }
    return $problems;
  }
}

final class Applier
{
  private const HBA_TYPES = ['host', 'hostssl', 'hostnossl', 'hostgssenc', 'hostnogssenc'];

  public function __construct(
    private readonly Connector $connector,
    private readonly Catalog $catalog,
    private readonly Options $opt,
  ) {}

  public function run(): int
  {
    $execute = $this->opt->has('execute');
    if ($execute) {
      $this->connector->requireTrusted('apply --execute');
    }
    $ctx = ServerContext::load($this->connector, $this->opt);
    if ($execute) {
      if (!$ctx->superuser) {
        throw new HardenException('apply --execute braucht einen Superuser (pg_reload_conf, pg_file_settings, Änderungen in allen Datenbanken).');
      }
      // Taken before the check: the plan must not go stale because another run changed the files in between.
      $lock = Connector::readOnly($this->connector->connect('postgres'), "SELECT pg_try_advisory_lock(hashtext('pg-harden-apply')) AS ok")[0]['ok'];
      if (!$lock) {
        throw new HardenException('Auf diesem Server läuft bereits ein apply oder rollback.');
      }
    }
    $before = Report::build($ctx, $this->catalog, (new Checker($this->connector, $ctx, $this->catalog))->run(), $this->opt, $this->connector);
    [$only, $confirmed] = $this->selection();
    $plan = $this->plan($before, $ctx, $only, $confirmed);

    fwrite(STDOUT, 'pg-harden ' . PG_HARDEN_VERSION . ' apply — ' . Text::printable($ctx->server) . ', PostgreSQL ' . Text::printable($ctx->version)
      . ', Benutzer ' . Text::printable($ctx->user) . "\n" . self::describe($plan));
    if ($plan['conf'] === [] && $plan['hba'] === [] && $plan['sql'] === []) {
      fwrite(STDOUT, "\nNichts auszuführen.\n");
      return Report::exitCode($before);
    }
    if (!$execute) {
      fwrite(STDOUT, "\nTrockenlauf — nichts geändert. Ausführen: --execute --dir=<NEUES_VERZEICHNIS> (Sicherungen und Journal).\n");
      return Report::exitCode($before);
    }
    $dir = $this->opt->get('dir') ?? throw new HardenException('apply --execute braucht --dir=<neues Verzeichnis> für Sicherungen und Journal.');
    Files::prepareDir($dir);
    $this->confirm();

    $journal = new Journal($dir, [
      'tool' => 'pg-harden ' . PG_HARDEN_VERSION,
      'started_at' => date(DATE_ATOM),
      'server' => $ctx->server,
      'server_version' => $ctx->version,
      'user' => $ctx->user,
      'identity' => (new ServerFiles($this->connector))->identity(),
    ]);
    Files::write($dir . '/report-before.json', Text::json($before), exclusive: true);

    $failed = false;
    if ($plan['conf'] !== [] || $plan['hba'] !== []) {
      $failed = !$this->applyFiles($plan, $ctx, $journal);
    }
    if (!$failed && $plan['sql'] !== []) {
      $failed = !$this->applySql($plan['sql'], $journal);
    }

    // New connections: settings of the backend/superuser-backend kind (log_connections, log_disconnections …) only reach new sessions.
    $after = null;
    $comparison = '';
    try {
      $post = new Connector($this->opt);
      $postCtx = ServerContext::load($post, $this->opt);
      $after = Report::build($postCtx, $this->catalog, (new Checker($post, $postCtx, $this->catalog))->run(), $this->opt, $post);
      $after['comparison'] = Verifier::compare($before, $after);
      Files::write($dir . '/report-after.json', Text::json($after), exclusive: true);
      $comparison = Verifier::renderText($after['comparison']);
    } catch (Throwable $e) {
      $failed = true;
      $comparison = "\nNachprüfung nicht möglich: " . Text::printable(strtok($e->getMessage(), "\n") ?: get_class($e)) . "\n";
    }
    try {
      $journal->data['finished_at'] = date(DATE_ATOM);
      $journal->data['failed'] = $failed;
      $journal->flush();
    } catch (Throwable) {
    }
    fwrite(STDOUT, "\n== Ergebnis ==\n" . self::summary($journal) . $comparison
      . "\nJournal, Sicherungen und Berichte: $dir\nRückgängig machen: php pg-harden.php rollback --dir=$dir (gleiche Verbindung)\n\n" . RESPONSIBILITY_NOTICE . "\n");
    return $failed || $after === null ? 2 : (Report::exitCode($after) === 1 ? 1 : (self::hasWarnings($journal) ? 3 : 0));
  }

  /** @return array{0: ?string[], 1: string[]} restriction to rule ids (null = all), ids released from "confirm" */
  private function selection(): array
  {
    $parse = function (string $key): ?array {
      $v = $this->opt->get($key);
      return $v === null ? null : array_values(array_filter(array_map('trim', explode(',', $v))));
    };
    $only = $parse('rules');
    $confirmed = $parse('include-confirm') ?? [];
    foreach (array_merge($only ?? [], $confirmed) as $id) {
      if (!isset($this->catalog->rules[$id])) {
        throw new HardenException('Unbekannte Regel ' . Text::printable($id) . ' (siehe rules).');
      }
    }
    foreach ($confirmed as $id) {
      if ($this->catalog->rules[$id]->automation() !== 'confirm') {
        throw new HardenException("--include-confirm: $id ist keine Regel mit automation \"confirm\".");
      }
    }
    return [$only, $confirmed];
  }

  private function confirm(): void
  {
    if ($this->opt->has('yes')) {
      return;
    }
    if (!function_exists('stream_isatty') || !stream_isatty(STDIN)) {
      throw new HardenException('apply --execute braucht --yes, wenn keine Eingabe möglich ist.');
    }
    fwrite(STDOUT, "\nDiese Änderungen jetzt ausführen? Zum Bestätigen \"ja\" eingeben: ");
    if (trim((string) fgets(STDIN)) !== 'ja') {
      throw new HardenException('Abgebrochen — nichts geändert.');
    }
  }

  /**
   * @return array{conf: array, hba: array, sql: array, skipped: array}
   */
  private function plan(array $report, ServerContext $ctx, ?array $only, array $confirmed): array
  {
    $plan = ['conf' => [], 'hba' => [], 'sql' => [], 'skipped' => [], 'notes' => []];
    $planner = new Planner($this->connector, $this->catalog);
    $confSettings = [];
    $requirements = [];
    foreach ($report['results'] as $r) {
      if ($r['status'] !== 'fail') {
        continue;
      }
      $rule = $this->catalog->rules[$r['id']];
      $fix = $rule->fix();
      if ($fix['type'] === 'manual' || $rule->automation() === 'manual') {
        continue;
      }
      if ($only !== null && !in_array($r['id'], $only, true)) {
        continue;
      }
      if ($rule->automation() === 'confirm' && !in_array($r['id'], $confirmed, true)) {
        $plan['skipped'][] = [$r['id'], 'braucht Freigabe: --include-confirm=' . $r['id']];
        continue;
      }
      match ($fix['type']) {
        'conf' => array_push($confSettings, ...array_map(fn($n) => [$r['id'], $n, (string) $fix['settings'][$n]], array_keys($fix['settings']))),
        'sql' => $this->planSql($r, $plan),
        'hba' => $this->planHba($r, $fix, $ctx, $plan, $requirements),
      };
    }
    if ($confSettings !== []) {
      $inspect = $planner->inspect(array_column($confSettings, 1));
      foreach ($confSettings as [$ruleId, $name, $value]) {
        if ($inspect['shadow'][$name] !== null) {
          $plan['skipped'][] = [$ruleId, "$name: " . $inspect['shadow'][$name] . ' (die Include-Datei würde nicht greifen)'];
          continue;
        }
        if (strtolower((string) ($inspect['current'][$name]['setting'] ?? '')) === strtolower($value)) {
          continue;
        }
        $plan['conf'][] = ['rule' => $ruleId, 'name' => $name, 'value' => $value, 'restart' => ($inspect['current'][$name]['context'] ?? '') === 'postmaster'];
      }
    }
    if (($plan['conf'] !== [] || $plan['hba'] !== []) && !Platform::windows()
      && (!function_exists('pcntl_async_signals') || !function_exists('posix_seteuid'))) {
      foreach (array_merge($plan['conf'], $plan['hba']) as $a) {
        $plan['skipped'][] = [$a['rule'], 'Dateiänderungen brauchen die PHP-Erweiterungen pcntl und posix (Schutz bei Abbruch und Identitätswechsel als root)'];
      }
      $plan['conf'] = $plan['hba'] = [];
    }
    if (($plan['conf'] !== [] || $plan['hba'] !== []) && $ctx->local === null) {
      foreach (array_merge($plan['conf'], $plan['hba']) as $a) {
        $plan['skipped'][] = [$a['rule'], 'Konfigurationsdateien liegen nicht auf diesem Rechner (' . $ctx->localNote . ')'];
      }
      $plan['conf'] = $plan['hba'] = [];
    }
    if ($plan['conf'] !== [] && $ctx->local !== null) {
      $confPath = $ctx->local->path('config_file');
      $config = $confPath === null ? null : Fs::attempt(fn() => file_get_contents($confPath));
      $dir = $config === null ? null : self::includeDir($config, $confPath);
      if ($config === null) {
        $plan['notes'][] = 'postgresql.conf nicht lesbar — apply würde die Datei nicht ändern können';
      } elseif ($dir === null) {
        $plan['notes'][] = 'postgresql.conf enthält kein aktives include_dir: am Ende wird "include_dir = \'conf.d\'" ergänzt (Sicherung der Datei, Verzeichnis ' . Text::printable(dirname($confPath) . '/conf.d') . ' wird angelegt)';
      } else {
        $plan['notes'][] = 'Include-Verzeichnis: ' . Text::printable($dir);
      }
    }
    return $plan;
  }

  private function planSql(array $result, array &$plan): void
  {
    foreach ($result['findings'] as $f) {
      $db = $f['database'] ?? $this->connector->entry;
      $why = match (true) {
        $f['fix_sql'] === null => 'kein Korrektur-SQL',
        $f['rollback_sql'] === null => 'kein Rückweg — apply ändert nichts ohne Rückweg',
        Text::hasControl($db) || Text::hasControl($f['object']) => 'Name mit Steuerzeichen',
        !ServerFiles::pairAllowed($f['fix_sql'], $f['rollback_sql']) => 'Korrektur-SQL ist keine einzelne einfache GRANT-, REVOKE- oder ALTER-ROUTINE-Anweisung mit passendem Rückweg',
        default => null,
      };
      if ($why !== null) {
        $plan['skipped'][] = [$result['id'], Text::printable($f['object']) . ': ' . $why];
        continue;
      }
      $plan['sql'][$db][] = ['rule' => $result['id'], 'object' => $f['object'], 'fix_sql' => $f['fix_sql'], 'rollback_sql' => $f['rollback_sql']];
    }
  }

  private function planHba(array $result, array $fix, ServerContext $ctx, array &$plan, array &$requirements): void
  {
    foreach ((array) ($fix['requires'] ?? []) as $req) {
      $key = $req . ':' . (in_array('trust', (array) $fix['from'], true) ? 'strict' : 'lenient');
      if (!array_key_exists($key, $requirements)) {
        $requirements[$key] = $this->requirement($req, (array) $fix['from'], $ctx);
      }
      if ($requirements[$key] !== null) {
        $plan['skipped'][] = [$result['id'], $requirements[$key]];
        return;
      }
    }
    foreach ($result['findings'] as $f) {
      if (!isset($f['hba_line'])) {
        continue;
      }
      if (!in_array($f['hba_type'], self::HBA_TYPES, true)) {
        $plan['skipped'][] = [$result['id'], 'Zeile ' . $f['hba_line'] . ': Zeilen vom Typ ' . Text::printable($f['hba_type']) . ' ändert apply nie (Zugang über den Unix-Socket bleibt)'];
        continue;
      }
      $plan['hba'][] = ['rule' => $result['id'], 'line' => $f['hba_line'], 'kind' => $fix['kind'], 'from' => (array) $fix['from'], 'to' => $fix['to']];
    }
  }

  /** @return ?string reason the change would risk a lockout, null if the requirement holds */
  private function requirement(string $name, array $from, ServerContext $ctx): ?string
  {
    $pdo = $this->connector->connect();
    if ($name === 'ssl_on') {
      $on = Connector::readOnly($pdo, "SELECT current_setting('ssl') = 'on' AS on")[0]['on'];
      if (!$on) {
        return 'ssl ist aus — hostssl würde alle TCP-Anmeldungen abweisen';
      }
      // Connections that exist right now without TLS from other hosts would be turned away at their next login.
      $plain = (int) Connector::readOnly($pdo, <<<'SQL'
        SELECT count(*) AS n
          FROM pg_stat_activity a
          JOIN pg_stat_ssl s ON s.pid = a.pid
         WHERE a.backend_type = 'client backend'
           AND a.client_addr IS NOT NULL
           AND NOT s.ssl
           AND NOT (a.client_addr <<= inet '127.0.0.0/8' OR a.client_addr = inet '::1')
        SQL)[0]['n'];
      return $plain === 0 ? null : "$plain bestehende Verbindung(en) von anderen Rechnern laufen ohne TLS und würden beim nächsten Anmelden abgewiesen — erst die Clients auf TLS umstellen";
    }
    if (!$ctx->superuser) {
      return 'braucht Superuser, um die Passwortformate zu prüfen';
    }
    // trust → scram also locks out roles without a password; md5/password → scram only roles with an md5 hash.
    $strict = in_array('trust', $from, true);
    $rows = Connector::readOnly($pdo, <<<SQL
      SELECT rolname
        FROM pg_authid
       WHERE rolcanlogin
         AND (rolpassword NOT LIKE 'SCRAM-SHA-256\$%' OR rolpassword IS NULL AND :strict)
       ORDER BY rolname
       LIMIT 10
      SQL, ['strict' => $strict ? 'true' : 'false']);
    if ($rows === []) {
      return null;
    }
    return 'Rollen ohne SCRAM-Passwort würden sich nicht mehr anmelden können: ' . Text::printable(implode(', ', array_column($rows, 'rolname')))
      . (count($rows) === 10 ? ' …' : '') . ' — erst Passwörter neu setzen';
  }

  private static function describe(array $plan): string
  {
    $out = '';
    if ($plan['conf'] !== []) {
      $out .= "\nParameter (Include-Datei conf.d/90-pg-harden.conf):\n";
      foreach ($plan['conf'] as $a) {
        $out .= "  - {$a['name']} = '{$a['value']}'  [{$a['rule']}]" . ($a['restart'] ? '  (Neustart nötig, wird nicht ausgeführt)' : '') . "\n";
      }
    }
    foreach ($plan['notes'] as $note) {
      $out .= '  · ' . $note . "\n";
    }
    if ($plan['hba'] !== []) {
      $out .= "\npg_hba.conf (Sicherung, Prüfung durch den Server, Anmeldetest nach dem Neuladen — der Test deckt nur die Anmeldung dieses Werkzeugs ab, nicht Anwendungen und andere Rollen):\n";
      foreach ($plan['hba'] as $a) {
        $out .= "  - Zeile {$a['line']}: " . ($a['kind'] === 'type' ? 'Typ' : 'Methode') . ' ' . implode('/', $a['from']) . " → {$a['to']}  [{$a['rule']}]\n";
      }
    }
    foreach ($plan['sql'] as $db => $items) {
      $out .= "\nSQL in Datenbank " . Text::printable((string) $db) . ":\n";
      foreach ($items as $i) {
        $out .= '  - ' . Text::printable($i['fix_sql']) . "  [{$i['rule']}]\n";
      }
    }
    if ($plan['skipped'] !== []) {
      $out .= "\nNicht ausgeführt:\n";
      $seen = [];
      foreach ($plan['skipped'] as [$id, $why]) {
        if (isset($seen[$id . $why])) {
          continue;
        }
        $seen[$id . $why] = true;
        $out .= "  - $id: $why\n";
      }
    }
    return $out;
  }

  private static function summary(Journal $j): string
  {
    $out = '';
    foreach ($j->data['steps'] as $s) {
      $out .= sprintf("  [%s] %s: %s\n", $s['status'], $s['phase'], Text::printable($s['message']));
    }
    return $out;
  }

  private static function hasWarnings(Journal $j): bool
  {
    return array_filter($j->data['steps'], fn($s) => $s['status'] === 'WARNUNG') !== [];
  }

  // ── files: pg_hba.conf and the include file ──────────────────────────────

  private function applyFiles(array $plan, ServerContext $ctx, Journal $journal): bool
  {
    $files = new ServerFiles($this->connector);
    $local = $ctx->local;
    $hbaPath = $local->path('hba_file');
    $confPath = $local->path('config_file');
    if ($hbaPath === null || $confPath === null) {
      $journal->step('Dateien', 'FEHLER', 'hba_file/config_file nicht sichtbar');
      return false;
    }
    $roots = array_values(array_filter([Fs::canonical($local->dataDir), Fs::canonical(dirname($confPath))]));
    $inside = function (?string $path) use ($roots): bool {
      $n = $path === null ? null : ServerFiles::norm($path);
      foreach ($roots as $root) {
        if ($n !== null && ($n === $root || str_starts_with($n, $root . '/'))) {
          return true;
        }
      }
      return false;
    };
    $config = Fs::attempt(fn() => file_get_contents($confPath));
    $includeDir = $config === null ? null : (self::includeDir($config, $confPath) ?? dirname($confPath) . '/conf.d');
    if (($plan['hba'] !== [] && !$inside($hbaPath)) || ($plan['conf'] !== [] && !$inside($includeDir))) {
      $journal->step('Dateien', 'FEHLER', 'hba_file bzw. Include-Verzeichnis liegen weder im Datenverzeichnis noch neben postgresql.conf — apply schreibt dort nicht');
      return false;
    }
    try {
      $preConfig = $files->configErrors();
      $preHba = $plan['hba'] !== [] ? $files->hbaErrors() : [];
      if ($preConfig !== [] || $preHba !== []) {
        $journal->step('Dateien', 'FEHLER', 'Server meldet bereits Fehler in der Konfiguration — erst beheben: ' . implode(' | ', array_merge($preConfig, $preHba)));
        return false;
      }
    } catch (Throwable $e) {
      $journal->step('Vorprüfung', 'FEHLER', (strtok($e->getMessage(), "\n") ?: get_class($e)) . ' — nichts geändert');
      return false;
    }
    try {
      $hbaRowsBefore = $plan['hba'] !== [] ? $files->hbaRows() : [];
      $hbaNew = $plan['hba'] !== [] ? $this->editHba($hbaPath, $plan['hba'], $hbaRowsBefore, $local, $journal) : null;
      $confNew = $plan['conf'] !== [] ? $this->prepareConf($plan['conf'], $confPath, $journal) : null;
      // Nothing on disk has changed yet. Prove write access to everything that will be overwritten before the first backup.
      if ($hbaNew !== null) {
        ServerFiles::assertWritable($hbaPath);
      }
      foreach ($confNew['writes'] ?? [] as $w) {
        if (Fs::attempt(fn() => is_file($w['path'])) === true) {
          ServerFiles::assertWritable($w['path']);
        }
      }
    } catch (Throwable $e) {
      $journal->step('Vorbereitung', 'FEHLER', (strtok($e->getMessage(), "\n") ?: get_class($e)) . ' — nichts geändert');
      return false;
    }

    // From here on the backups are the way back — also if this process dies (Guard) or throws anything at all.
    Guard::arm($journal, $files);
    try {
      try {
        if ($hbaNew !== null) {
          $journal->file($hbaPath, 'modified', $journal->backup($hbaPath));
          $this->assertUnchanged($journal, $hbaNew['base']);
          ServerFiles::overwrite($hbaPath, $hbaNew['content']);
        }
        foreach ($confNew['writes'] ?? [] as $w) {
          if ($w['mkdir'] ?? false) {
            // include_dir points to a directory that does not exist yet; recorded first, so a restore removes the file before it.
            $journal->file($w['mkdir'], 'created', null);
            try {
              ServerFiles::makeDir($w['mkdir'], dirname($w['mkdir']));
            } catch (HardenException $e) {
              $journal->forgetLast();
              throw $e;
            }
          }
          $existed = Fs::asOwnerOf($w['path'], fn() => Fs::attempt(fn() => is_file($w['path']))) === true;
          if ($existed) {
            $journal->file($w['path'], 'modified', $journal->backup($w['path']));
            $this->assertUnchanged($journal, $w['base']);
            ServerFiles::overwrite($w['path'], $w['content']);
          } else {
            $journal->file($w['path'], 'created', null);
            try {
              ServerFiles::create($w['path'], $w['content'], $confPath);
            } catch (HardenException $e) {
              $journal->forgetLast();
              throw $e;
            }
          }
        }
      } catch (HardenException $e) {
        return $this->fail($files, $journal, 'Schreiben', $e->getMessage());
      }

      // The server reads the files from disk for these two views: validate before anything is reloaded.
      $errors = array_merge($files->configErrors(), $plan['hba'] !== [] ? $files->hbaErrors() : []);
      if ($errors === [] && $hbaNew !== null) {
        $errors = $this->compareHba($hbaRowsBefore, $files->hbaRows(), $hbaNew['edits']);
      }
      if ($errors === [] && $plan['hba'] !== [] && !Platform::windows() && !$this->hasLocalLine($files->hbaRows())) {
        $errors[] = 'kein local-Eintrag mehr in pg_hba.conf — Zugang über den Unix-Socket ginge verloren';
      }
      if ($errors !== []) {
        return $this->fail($files, $journal, 'Prüfung durch den Server', implode(' | ', $errors), reload: false);
      }
      $journal->step('Prüfung durch den Server', 'OK', 'pg_hba_file_rules und pg_file_settings ohne Fehler');

      [$reloaded, $why] = $files->reload();
      if (!$reloaded) {
        // An unconfirmed reload means the login test below would still look at the OLD configuration: not a success.
        return $this->fail($files, $journal, 'Neuladen', $why);
      }
      $journal->step('Neuladen', 'OK', 'Konfiguration neu geladen');
      [$works, $problem] = $files->newLoginWorks();
      if (!$works) {
        return $this->fail($files, $journal, 'Anmeldetest nach dem Neuladen', 'neue Anmeldung scheitert: ' . $problem);
      }
      $journal->step('Anmeldetest', 'OK', 'neue Anmeldung mit denselben Zugangsdaten funktioniert (geprüft ist nur diese Anmeldung, nicht Anwendungen und andere Rollen)');
      foreach ($plan['conf'] as $a) {
        if ($a['restart']) {
          $journal->step('Neustart', 'WARNUNG', "{$a['name']} wirkt erst nach einem Neustart des Servers (nicht ausgeführt)");
        }
      }
      return true;
    } catch (Throwable $e) {
      return $this->fail($files, $journal, 'Unerwarteter Fehler', strtok($e->getMessage(), "\n") ?: get_class($e));
    } finally {
      Guard::disarm();
    }
  }

  /** The content the new file was computed from must be what the backup just read: nobody changed the file in between. */
  private function assertUnchanged(Journal $journal, ?string $base): void
  {
    $last = end($journal->data['files']);
    $backup = Fs::attempt(fn() => file_get_contents($journal->dir . '/' . $last['backup']));
    if ($base === null || $backup !== $base) {
      throw new HardenException(Text::printable(basename($last['path'])) . ' hat sich seit der Planung geändert — abgebrochen, bitte erneut planen.');
    }
  }

  /** Restores the backups, reloads, proves a new login works again. Always returns false (the run failed). */
  private function fail(ServerFiles $files, Journal $journal, string $phase, string $message, bool $reload = true): bool
  {
    // The files come first: a journal that cannot be written (full disk, the very reason for the failure) must not stop the restore.
    $note = function (string $p, string $status, string $m) use ($journal): void {
      try {
        $journal->step($p, $status, $m);
      } catch (Throwable) {
        fwrite(STDERR, 'pg-harden: ' . Text::printable("$p [$status] $m") . "\n");
      }
    };
    $problems = [];
    try {
      $problems = ServerFiles::restore($journal->data['files'], $journal->dir);
    } catch (Throwable $e) {
      $problems[] = strtok($e->getMessage(), "\n") ?: get_class($e);
    }
    $note($phase, 'FEHLER', $message);
    $note('Wiederherstellung', $problems === [] ? 'OK' : 'FEHLER', $problems === [] ? 'Sicherungen zurückgespielt' : implode(' | ', $problems) . ' — Sicherungen im Journal-Verzeichnis, von Hand zurückspielen');
    if ($problems === [] && $reload) {
      try {
        [$ok, $why] = $files->reload();
        [$works, $problem] = $files->newLoginWorks();
        $note('Wiederherstellung', $ok && $works ? 'OK' : 'FEHLER',
          $ok && $works ? 'Konfiguration mit dem alten Stand neu geladen, neue Anmeldung funktioniert' : 'nach der Wiederherstellung: ' . ($ok ? $problem : $why) . ' — Sicherungen im Journal-Verzeichnis, von Hand prüfen');
      } catch (Throwable $e) {
        $note('Wiederherstellung', 'FEHLER', 'Neuladen nach der Wiederherstellung fehlgeschlagen: ' . (strtok($e->getMessage(), "\n") ?: get_class($e)));
      }
    }
    return false;
  }

  private function hasLocalLine(array $rows): bool
  {
    foreach ($rows as $r) {
      if ($r['type'] === 'local' && $r['error'] === null && $r['auth_method'] !== 'reject') {
        return true;
      }
    }
    return false;
  }

  /** @return array{content: string, edits: array<int, array{type?: string, method?: string}>} */
  private function editHba(string $path, array $actions, array $rowsBefore, LocalServer $local, Journal $journal): array
  {
    $content = Fs::attempt(fn() => file_get_contents($path));
    if ($content === null) {
      throw new HardenException('pg_hba.conf nicht lesbar: ' . Text::printable($path));
    }
    $lines = preg_split('/(?<=\n)/', $content, -1, PREG_SPLIT_NO_EMPTY);
    $byLine = [];
    foreach ($rowsBefore as $row) {
      $sameFile = !isset($row['file_name']) || Fs::canonical((string) $row['file_name']) === Fs::canonical($path);
      if ($sameFile) {
        $byLine[(int) $row['line_number']] = $row;
      }
    }
    $edits = [];
    foreach ($actions as $a) {
      $n = $a['line'];
      $row = $byLine[$n] ?? null;
      $line = $lines[$n - 1] ?? null;
      if ($row === null || $line === null || HbaFile::continues($line)) {
        throw new HardenException("Zeile $n von pg_hba.conf ist nicht eindeutig bearbeitbar (Include-Datei, Fortsetzungszeile oder geändert seit der Prüfung)");
      }
      if ($a['kind'] === 'type') {
        $new = HbaFile::replaceToken($line, 0, $a['from'], $a['to']);
        $edits[$n]['type'] = $a['to'];
      } else {
        $idx = HbaFile::methodIndex($line, (string) $row['type']);
        $new = $idx === null ? null : HbaFile::replaceToken($line, $idx, $a['from'], $a['to']);
        $edits[$n]['method'] = $a['to'];
      }
      if ($new === null) {
        throw new HardenException("Zeile $n von pg_hba.conf hat nicht die erwartete Form (" . implode('/', $a['from']) . ' → ' . $a['to'] . ')');
      }
      $lines[$n - 1] = $new;
    }
    return ['content' => implode('', $lines), 'edits' => $edits, 'base' => $content];
  }

  /** Every rule must be identical to before, except the fields that were meant to change. @return string[] */
  private function compareHba(array $before, array $after, array $edits): array
  {
    if (count($before) !== count($after)) {
      return ['Anzahl der Regeln hat sich geändert (' . count($before) . ' → ' . count($after) . ')'];
    }
    $fields = ['type', 'database', 'user_name', 'address', 'netmask', 'auth_method', 'options'];
    $errors = [];
    foreach ($before as $i => $b) {
      $a = $after[$i];
      $expected = $b;
      $n = (int) $b['line_number'];
      if (isset($edits[$n]['type'])) {
        $expected['type'] = $edits[$n]['type'];
      }
      if (isset($edits[$n]['method'])) {
        $expected['auth_method'] = $edits[$n]['method'];
      }
      foreach ($fields as $f) {
        if (($a[$f] ?? null) !== ($expected[$f] ?? null)) {
          $errors[] = "Zeile $n: Feld $f weicht vom erwarteten Ergebnis ab";
        }
      }
    }
    return $errors;
  }

  /** @return array{writes: array} files to write: the include file, and postgresql.conf when include_dir is missing */
  private function prepareConf(array $settings, string $confPath, Journal $journal): array
  {
    $writes = [];
    $config = Fs::attempt(fn() => file_get_contents($confPath));
    if ($config === null) {
      throw new HardenException('postgresql.conf nicht lesbar: ' . Text::printable($confPath));
    }
    $includeDir = self::includeDir($config, $confPath);
    $mkdir = null;
    if ($includeDir === null) {
      $includeDir = dirname($confPath) . '/conf.d';
      $nl = str_contains($config, "\r\n") ? "\r\n" : "\n";
      $append = (str_ends_with($config, "\n") ? '' : $nl) . $nl . '# pg-harden ' . PG_HARDEN_VERSION . ': Include-Verzeichnis für 90-pg-harden.conf (Rückweg: Zeile entfernen)' . $nl
        . "include_dir = 'conf.d'" . $nl;
      $writes[] = ['path' => $confPath, 'content' => $config . $append, 'base' => $config];
      if (Fs::attempt(fn() => is_dir($includeDir)) !== true) {
        $mkdir = $includeDir;
      }
    } elseif (Fs::attempt(fn() => is_dir($includeDir)) !== true) {
      $mkdir = $includeDir;
    }
    $target = $includeDir . '/90-pg-harden.conf';
    $existing = Fs::attempt(fn() => file_get_contents($target));
    $writes[] = ['path' => $target, 'content' => self::renderConf($settings, $existing), 'mkdir' => $mkdir, 'base' => $existing];
    return ['writes' => $writes];
  }

  /** First active include_dir of postgresql.conf, resolved relative to that file; null if there is none. */
  public static function includeDir(string $config, string $confPath): ?string
  {
    foreach (preg_split('/\r\n|\n|\r/', $config) as $line) {
      if (preg_match("/^\s*include_dir\s*(?:=\s*)?(?:'((?:[^'\\\\]|\\\\.|'')*)'|([^\s#']+))/", $line, $m) === 1) {
        $dir = strtr($m[1] !== '' ? $m[1] : ($m[2] ?? ''), ["''" => "'", '\\\\' => '\\']);
        return Fs::isAbsolute($dir) ? $dir : dirname($confPath) . '/' . $dir;
      }
    }
    return null;
  }

  /** Keeps parameters of an earlier run that this run does not touch. */
  public static function renderConf(array $settings, ?string $existing): string
  {
    $values = [];
    $foreign = [];
    foreach (preg_split('/\r\n|\n|\r/', (string) $existing) as $line) {
      if (preg_match("/^\s*([a-z_][a-z0-9_.]*)\s*=\s*'((?:[^'\\\\]|\\\\.|'')*)'\s*$/", $line, $m) === 1) {
        $values[$m[1]] = strtr($m[2], ["''" => "'", '\\\\' => '\\']);
      } elseif (trim($line) !== '' && !str_starts_with(ltrim($line), '#')) {
        $foreign[] = $line;
      }
    }
    // A foreign line is read after the generated ones and would win: drop those that set a parameter written now.
    $names = array_column($settings, 'name');
    $foreign = array_values(array_filter($foreign, fn($l) => !in_array(strtolower((string) (preg_split('/[\s=]/', ltrim($l))[0] ?? '')), $names, true)));
    $rules = [];
    foreach ($settings as $s) {
      $values[$s['name']] = $s['value'];
      $rules[$s['name']] = $s['rule'];
    }
    $lines = [
      '# pg-harden ' . PG_HARDEN_VERSION . ' — geschrieben von apply, ' . date('Y-m-d H:i'),
      '# ' . RESPONSIBILITY_NOTICE,
      '# Zurücknehmen: Datei entfernen (oder pg-harden rollback) und Konfiguration neu laden.',
      '',
    ];
    foreach ($values as $name => $value) {
      $lines[] = ($rules[$name] ?? null) !== null ? "# {$rules[$name]}" : '# aus einem früheren Lauf';
      $lines[] = $name . " = '" . strtr($value, ['\\' => '\\\\', "'" => "''"]) . "'";
    }
    if ($foreign !== []) {
      $lines[] = '';
      $lines[] = '# Zeilen der vorhandenen Datei, die pg-harden nicht versteht — unverändert übernommen:';
      array_push($lines, ...$foreign);
    }
    return implode("\n", $lines) . "\n";
  }

  // ── SQL ──────────────────────────────────────────────────────────────────

  private function applySql(array $byDb, Journal $journal): bool
  {
    $allOk = true;
    foreach ($byDb as $db => $items) {
      $db = (string) $db;
      $pdo = null;
      $indexes = [];
      $committing = false;
      try {
        $pdo = $this->connector->connectWritable($db);
        $pdo->exec('BEGIN');
        $pdo->exec("SET LOCAL lock_timeout = '5s'");
        $right = $pdo->query('SELECT current_database() AS d')->fetch()['d'];
        if ($right !== $db) {
          throw new HardenException('verbunden mit falscher Datenbank');
        }
        foreach ($items as $i) {
          // prepare() lets the server refuse anything but exactly one statement.
          $pdo->prepare($i['fix_sql'])->execute();
        }
        // The way back is on disk BEFORE the commit: a crash right after it must not lose it.
        foreach ($items as $i) {
          $indexes[] = $journal->sql($db, $i['rule'], $i['fix_sql'], $i['rollback_sql']);
        }
        $committing = true;
        $pdo->exec('COMMIT');
        $pdo = null; // release the connection (template1 must not stay occupied: CREATE DATABASE would fail)
        foreach ($indexes as $ix) {
          $journal->markSql($ix, 'committed');
        }
        $journal->step('SQL', 'OK', count($items) . ' Anweisung(en) in Datenbank ' . $db);
      } catch (Throwable $e) {
        if ($pdo !== null) {
          try {
            $pdo->exec('ROLLBACK');
          } catch (Throwable) {
          }
        }
        $reason = strtok($e->getMessage(), "\n") ?: get_class($e);
        try {
          if ($committing) {
            // The outcome of COMMIT is unknown: the entries stay "pending" and rollback will run them (they are idempotent).
            $journal->step('SQL', 'FEHLER', 'Datenbank ' . $db . ': Ausgang des Commit unklar (' . $reason . ') — Journal enthält den Rückweg, Zustand prüfen');
          } else {
            foreach ($indexes as $ix) {
              $journal->markSql($ix, 'failed');
            }
            $journal->step('SQL', 'FEHLER', 'Datenbank ' . $db . ' unverändert: ' . $reason);
          }
        } catch (Throwable) {
          fwrite(STDERR, "pg-harden: Journal nicht beschreibbar — Zustand von Datenbank $db prüfen.\n");
        }
        $allOk = false;
      }
    }
    return $allOk;
  }
}

/** `rollback --dir=<apply journal>`: files from the backups, SQL from the recorded rollback statements. */
final class Rollback
{
  public function __construct(private readonly Connector $connector, private readonly Options $opt) {}

  public function run(): int
  {
    $this->connector->requireTrusted('rollback');
    $dir = $this->opt->get('dir') ?? throw new HardenException('rollback braucht --dir=<Journal-Verzeichnis von apply>');
    $data = Journal::load($dir);
    $logFile = $dir . '/rollback-log.json';
    if (Fs::attempt(fn() => file_exists($logFile)) === true) {
      throw new HardenException('Dieses Journal wurde bereits zurückgenommen (rollback-log.json).');
    }
    $ctx = ServerContext::load($this->connector, $this->opt);
    if (!$ctx->superuser) {
      throw new HardenException('rollback braucht einen Superuser.');
    }
    $files = new ServerFiles($this->connector);
    $identity = $files->identity();
    if (($data['identity'] ?? null) !== $identity) {
      throw new HardenException('Das Journal gehört zu einem anderen Cluster (Systemkennung oder Datenverzeichnis weichen ab) — nichts geändert.');
    }
    $lock = Connector::readOnly($this->connector->connect('postgres'), "SELECT pg_try_advisory_lock(hashtext('pg-harden-apply')) AS ok")[0]['ok'];
    if (!$lock) {
      throw new HardenException('Auf diesem Server läuft bereits ein apply oder rollback.');
    }
    if ($data['files'] !== []) {
      if ($ctx->local === null) {
        throw new HardenException('Die Dateien lassen sich nur auf dem Server selbst zurückspielen (' . $ctx->localNote . ').');
      }
      $allowed = ServerFiles::allowedTargets($ctx->local);
      foreach ($data['files'] as $f) {
        if (!in_array(ServerFiles::norm($f['path']), $allowed, true)) {
          throw new HardenException('Das Journal nennt einen Pfad, den apply auf diesem Server nie schreiben würde: ' . Text::printable($f['path']) . ' — nichts geändert.');
        }
      }
    }
    $log = ['started_at' => date(DATE_ATOM), 'steps' => []];
    $step = function (string $status, string $message) use (&$log): void {
      $log['steps'][] = ['status' => $status, 'message' => $message];
      fwrite(STDOUT, "  [$status] " . Text::printable($message) . "\n");
    };
    $ok = true;
    if ($data['files'] !== []) {
      $problems = ServerFiles::restore($data['files'], $dir);
      $step($problems === [] ? 'OK' : 'FEHLER', $problems === [] ? count($data['files']) . ' Datei(en) zurückgespielt' : implode(' | ', $problems));
      $ok = $problems === [];
      $errors = array_merge($files->configErrors(), $files->hbaErrors());
      if ($errors !== []) {
        $step('FEHLER', 'Server meldet nach dem Zurückspielen Fehler: ' . implode(' | ', $errors));
        $ok = false;
      }
      if ($problems === [] && $errors === []) {
        [$reloaded, $why] = $files->reload();
        $step($reloaded ? 'OK' : 'FEHLER', $reloaded ? 'Konfiguration neu geladen' : $why);
        [$works, $problem] = $files->newLoginWorks();
        $step($works ? 'OK' : 'FEHLER', $works ? 'neue Anmeldung funktioniert' : 'neue Anmeldung scheitert: ' . $problem);
        $ok = $ok && $reloaded && $works;
      } else {
        $step('FEHLER', 'Nicht neu geladen: die Dateien sind nicht vollständig zurückgespielt — von Hand prüfen');
        $ok = false;
      }
    }
    $byDb = [];
    foreach (array_reverse($data['sql']) as $s) {
      if ($s['status'] === 'failed') {
        continue;
      }
      if (!ServerFiles::pairAllowed($s['fix_sql'] ?? null, $s['rollback_sql'] ?? null)) {
        $step('WARNUNG', 'Kein sicherer Rückweg für ' . $s['rule'] . ' in ' . $s['database'] . ' — von Hand prüfen');
        $ok = false;
        continue;
      }
      $byDb[$s['database']][] = $s['rollback_sql'];
    }
    foreach ($byDb as $db => $statements) {
      $pdo = null;
      try {
        $pdo = $this->connector->connectWritable((string) $db);
        $pdo->exec('BEGIN');
        $pdo->exec("SET LOCAL lock_timeout = '5s'");
        foreach ($statements as $sql) {
          $stmt = $pdo->prepare($sql);
          $stmt->execute();
        }
        $pdo->exec('COMMIT');
        $pdo = null; // release the connection (template1 must not stay occupied: CREATE DATABASE would fail)
        $step('OK', count($statements) . ' Rückweg-Anweisung(en) in Datenbank ' . $db);
      } catch (Throwable $e) {
        if ($pdo !== null) {
          try {
            $pdo->exec('ROLLBACK');
          } catch (Throwable) {
          }
        }
        $step('FEHLER', 'Datenbank ' . $db . ' unverändert: ' . (strtok($e->getMessage(), "\n") ?: get_class($e)));
        $ok = false;
      }
    }
    $log['finished_at'] = date(DATE_ATOM);
    $log['ok'] = $ok;
    // Only a complete rollback closes the journal; a failed attempt is kept under its own name and may be repeated.
    Files::write($ok ? $logFile : $dir . '/rollback-attempt-' . date('Ymd-His') . '.json', Text::json($log), exclusive: true);
    fwrite(STDOUT, "\nRückweg " . ($ok ? 'abgeschlossen' : 'unvollständig — Journal prüfen') . ".\n\n" . RESPONSIBILITY_NOTICE . "\n");
    return $ok ? 0 : 2;
  }
}
