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
    if (Fs::attempt(fn() => mkdir($dir . '/backup', 0700)) !== true) {
      throw new HardenException("Verzeichnis $dir/backup lässt sich nicht anlegen.");
    }
    $this->data = $header + ['journal_version' => self::VERSION, 'steps' => [], 'files' => [], 'sql' => []];
    $this->flush();
  }

  /** The journal drives writes with elevated rights: it is only trusted if nobody else could have touched it. */
  public static function load(string $dir): array
  {
    if (!Platform::windows()) {
      // Without posix the owner cannot be compared — and a journal without that check could carry any SQL way back.
      if (!function_exists('posix_geteuid')) {
        throw new HardenException('Die PHP-Erweiterung posix fehlt — ohne sie lässt sich nicht prüfen, wem das Journal gehört; dem Journal wird nicht vertraut.');
      }
      $st = Fs::attempt(fn() => stat($dir));
      if ($st === null || $st['uid'] !== posix_geteuid() || ($st['mode'] & 0077) !== 0) {
        throw new HardenException("$dir gehört nicht dem ausführenden Benutzer oder ist für andere zugänglich — dem Journal wird nicht vertraut.");
      }
    }
    if (Platform::windows()) {
      if (!WindowsFacts::isStrictlyPrivate($dir)) {
        throw new HardenException("$dir gehört nicht diesem Konto bzw. den Administratoren, ist für andere Konten zugänglich oder die ACL ist nicht lesbar — dem Journal wird nicht vertraut.");
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
    $release = WindowsPin::verifyTarget($path, mustExist: false);
    try {
      // Read with the identity Fs::asOwnerOf chooses for the way: a symlink planted by the service account leads nowhere new.
      $exists = Fs::asOwnerOf($path, fn() => Fs::attempt(fn() => is_file($path)));
      if ($exists !== true) {
        return null;
      }
      $content = Fs::readServerFile($path);
      $name = sprintf('backup/%02d-%s', count($this->data['files']) + 1, preg_replace('/[^A-Za-z0-9._-]/', '_', basename($path)));
      $fh = $content === null ? null : Fs::attempt(fn() => fopen($this->dir . '/' . $name, 'x'));
      $written = is_resource($fh) && Fs::attempt(fn() => fwrite($fh, $content)) === strlen($content);
      $closed = is_resource($fh) && Fs::attempt(fn() => fclose($fh)) === true;
      if (!$written || !$closed) {
        throw new HardenException('Sicherung von ' . Text::printable($path) . ' fehlgeschlagen — nichts wurde geändert.');
      }
      Fs::attempt(fn() => chmod($this->dir . '/' . $name, 0600));
      return $name;
    } finally {
      $release();
    }
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

  /** @param string[] $roots the server's directories WindowsPin holds (Windows): the restore rebuilds the hold over them */
  public static function arm(Journal $journal, ServerFiles $files, array $roots = []): void
  {
    self::$active = ['journal' => $journal, 'files' => $files, 'roots' => $roots];
    if (self::$registered) {
      return;
    }
    self::$registered = true;
    register_shutdown_function([self::class, 'onShutdown']);
    if (function_exists('pcntl_async_signals') && function_exists('pcntl_signal')) {
      pcntl_async_signals(true);
      foreach ([SIGINT, SIGTERM, SIGHUP, SIGQUIT] as $signal) {
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
    ['journal' => $journal, 'files' => $files, 'roots' => $roots] = self::$active;
    self::$active = null;
    // Restoring in a foreign identity could write where it must not: leave the backups to the operator.
    if (Fs::$identityLost) {
      Out::err('pg-harden: nichts zurückgespielt. Sicherungen und Journal: ' . Text::printable($journal->dir) . "\n");
      return;
    }
    // exit() skips finally blocks: a signal inside Fs::asOwnerOf must not leave this process as the service account
    // (becomeRoot ends the process at once if that fails).
    if (function_exists('posix_seteuid') && function_exists('posix_initgroups') && posix_getuid() === 0) {
      Fs::becomeRoot();
    }
    // A second Ctrl+C must not interrupt the restore.
    if (function_exists('pcntl_signal')) {
      foreach ([SIGINT, SIGTERM, SIGHUP, SIGQUIT] as $signal) {
        pcntl_signal($signal, SIG_IGN);
      }
    } elseif (function_exists('sapi_windows_set_ctrl_handler')) {
      sapi_windows_set_ctrl_handler(fn() => true);
    }
    try {
      $problems = ServerFiles::restore($journal->data['files'], $journal->dir, $roots);
      if ($problems === []) {
        $files->reload();
      }
      try {
        $journal->step('Abbruch', 'FEHLER', 'Lauf unterbrochen — Sicherungen ' . ($problems === [] ? 'zurückgespielt und Konfiguration neu geladen' : 'nur teilweise zurückgespielt: ' . implode(' | ', $problems)));
      } catch (Throwable) {
      }
    } catch (Throwable) {
      // Last resort: nothing more to do than to tell the operator where the backups are.
    } finally {
      WindowsPin::end();
    }
    try {
      Out::err('pg-harden: Lauf unterbrochen. Sicherungen und Journal: ' . Text::printable($journal->dir) . "\n");
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

  /**
   * Comparable form of a path that may not exist yet: the nearest existing ancestor resolved, the missing rest appended
   * (what does not exist cannot be a link). A repeated rollback needs this — the first one already removed conf.d.
   * Bounded by the number of path components; "." or ".." in the missing rest is never comparable.
   */
  public static function norm(string $path): ?string
  {
    $tail = [];
    for ($p = $path; ($c = Fs::canonical($p)) === null; $p = $parent) {
      $parent = dirname($p);
      $name = basename($p);
      // Only what an ancestor's listing proves missing counts as missing — a dangling link or a place without access does not.
      if ($parent === $p || $name === '.' || $name === '..' || $name === '' || !Fs::definitelyAbsent($p)) {
        return null;
      }
      array_unshift($tail, Platform::windows() ? strtolower($name) : $name);
    }
    return $tail === [] ? $c : rtrim($c, '/') . '/' . implode('/', $tail);
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
    $config = $conf === null ? null : Fs::readServerFile($conf);
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
   * copied, then rename — only if the temp file then has the owner and group of the original. Otherwise (Windows,
   * directory not writable, a file of root in the service account's directory, a group the identity is not a member of)
   * the new content is written in place first and the file shortened afterwards. As root, the work happens with the
   * identity Fs::asOwnerOf chooses for the way; on Windows, WindowsPin holds the target directory open against rename/delete
   * and verifies the final path before writing.
   */
  public static function overwrite(string $path, string $content): void
  {
    $release = WindowsPin::verifyTarget($path, mustExist: true);
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
              // Renaming would hand the file to another owner or group: write in place instead, which keeps both.
              $new = Fs::attempt(fn() => stat($tmp));
              $same = $new !== null && $new['uid'] === $st['uid'] && $new['gid'] === $st['gid'];
              // A file mounted on its own (container bind mount) cannot be replaced: fall back to writing in place.
              if ($same && Fs::attempt(fn() => rename($tmp, $path)) === true) {
                return;
              }
            } finally {
              Fs::attempt(fn() => file_exists($tmp) && unlink($tmp));
            }
          }
        }
        $fh = Fs::attempt(fn() => fopen($path, 'r+'));
        if (!is_resource($fh)) {
          throw new HardenException('Keine Schreibrechte auf ' . Text::printable($path) . Fs::identityNote() . '.');
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
    } finally {
      $release();
    }
  }

  /** New directory with the owner and group of its parent (as root a plain mkdir would lock the server out of it). */
  public static function makeDir(string $dir, string $parent): void
  {
    $release = WindowsPin::verifyTarget($dir, mustExist: false);
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
      WindowsPin::pinCreatedDir($dir);
    } catch (ErrorException $e) {
      throw new HardenException('Verzeichnis ' . Text::printable($dir) . ' lässt sich nicht anlegen: ' . $e->getMessage());
    } finally {
      $release();
    }
  }

  public static function assertWritable(string $path): void
  {
    [$fh, $note] = Fs::asOwnerOf($path, fn() => [Fs::attempt(fn() => fopen($path, 'r+')), Fs::identityNote()]);
    if (!is_resource($fh)) {
      throw new HardenException('Keine Schreibrechte auf ' . Text::printable($path) . $note . '.');
    }
    fclose($fh);
  }

  /** New file next to an existing sibling: same mode and (as root) the same owner and group. */
  public static function create(string $path, string $content, string $sibling): void
  {
    // On Windows the helper makes the empty file as the entry itself and holds it (verifyTarget create); PHP writes into it
    $release = WindowsPin::verifyTarget($path, mustExist: false, create: true);
    try {
      Fs::asOwnerOf($path, function () use ($path, $content, $sibling, $release): void {
        $fh = Fs::attempt(fn() => fopen($path, Platform::windows() ? 'r+' : 'x'));
        if (!is_resource($fh)) {
          if (Platform::windows()) {
            // The empty file the helper made must not stay behind unrecorded
            $release();
            Fs::attempt(fn() => unlink($path));
          }
          throw new HardenException('Datei ' . Text::printable($path) . ' lässt sich nicht anlegen (Rechte oder Verzeichnis fehlt).');
        }
        // The caller forgets the journal entry for a failed create: the half-written file must not stay behind unrecorded —
        // also when the failure arrives as an exception (a write notice on a full disk becomes an ErrorException).
        try {
          $ok = self::writeAll($fh, $content);
        } catch (Throwable $e) {
          $ok = false;
        }
        Fs::attempt(fn() => fclose($fh));
        if (!$ok) {
          // The held handle would block the removal: released first (the finally below releases once more, which is harmless)
          $release();
          Fs::attempt(fn() => unlink($path));
          throw new HardenException('Schreiben von ' . Text::printable($path) . ' fehlgeschlagen' . (isset($e) ? ': ' . $e->getMessage() : '') . '.');
        }
        $st = Fs::attempt(fn() => stat($sibling));
        if ($st !== null && !Platform::windows()) {
          Fs::attempt(fn() => chmod($path, ($st['mode'] & 0660) ?: 0640));
          if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            Fs::attempt(fn() => chown($path, $st['uid']));
            Fs::attempt(fn() => chgrp($path, $st['gid']));
          }
        }
      });
    } catch (ErrorException $e) {
      throw new HardenException('Datei ' . Text::printable($path) . ' lässt sich nicht anlegen: ' . $e->getMessage());
    } finally {
      $release();
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

  /**
   * Restores backups (modified files) and removes created files and directories, newest first. On Windows with $roots (the server's
   * directories of WindowsPin) the hold is (re)built first — a helper that ended or was released after a failed check must not leave
   * the backups unrestored; a way that redirects now refuses the restore as it refused the write.
   *
   * @param string[] $roots
   * @return string[] problems
   */
  public static function restore(array $files, string $journalDir, array $roots = []): array
  {
    $problems = [];
    if (Platform::windows() && $roots !== [] && $files !== []) {
      try {
        WindowsPin::begin($roots, array_column($files, 'path'));
      } catch (Throwable $e) {
        return [(strtok($e->getMessage(), "\n") ?: get_class($e)) . ' — nichts zurückgespielt'];
      }
    }
    foreach (array_reverse($files) as $f) {
      try {
        if ($f['action'] === 'created') {
          // Already gone (an interrupted or failed earlier rollback): nothing to remove, and no owner to take over.
          if (Fs::definitelyAbsent($f['path'])) {
            continue;
          }
          // Not held: the own handle would block the removal, and removing a link removes only the link
          $release = WindowsPin::verifyTarget($f['path'], mustExist: false, hold: false);
          try {
            if (Platform::windows() && Fs::attempt(fn() => is_dir($f['path'])) === true) {
              WindowsPin::unpinDirForRemove($f['path']);
            }
            Fs::asOwnerOf($f['path'], function () use ($f): void {
              if (file_exists($f['path'])) {
                $removed = is_dir($f['path']) ? rmdir($f['path']) : unlink($f['path']);
                if (!$removed) {
                  throw new HardenException('Eintrag ' . $f['path'] . ' ließ sich nicht entfernen');
                }
              }
            });
          } finally {
            $release();
          }
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

  /** @var string[] the server's directories WindowsPin holds in the file phase; fail() rebuilds the hold over them before it restores */
  private array $pinRoots = [];

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

    Out::write('pg-harden ' . PG_HARDEN_VERSION . ' · apply · ' . ($execute ? 'Ausführung' : 'Trockenlauf') . ' · ' . TextRenderer::when(date(DATE_ATOM)) . "\n"
      . TextRenderer::field('Server', Text::printable($ctx->server) . ' · PostgreSQL ' . Text::printable($ctx->version) . ' · Benutzer ' . Text::printable($ctx->user))
      . self::describe($plan));
    if ($plan['conf'] === [] && $plan['hba'] === [] && $plan['sql'] === []) {
      Out::write("\nNichts auszuführen.\n" . TextRenderer::notices(null));
      return Report::exitCode($before);
    }
    if (!$execute) {
      Out::write("\nTrockenlauf — nichts geändert. Ausführen mit --execute --dir=<NEUES_VERZEICHNIS> (Sicherungen und Journal).\n" . TextRenderer::notices(null));
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
    $failed = false;
    $after = null;
    $postError = null;
    $completed = false;
    try {
      Files::write($dir . '/report-before.json', Text::json($before), exclusive: true);
      if ($plan['conf'] !== [] || $plan['hba'] !== []) {
        $failed = !$this->applyFiles($plan, $ctx, $journal);
      }
      if (!$failed && $plan['sql'] !== []) {
        $failed = !$this->applySql($plan['sql'], $journal);
      }

      // New connections: settings of the backend/superuser-backend kind (log_connections, log_disconnections …) only reach new sessions.
      try {
        $post = new Connector($this->opt);
        $postCtx = ServerContext::load($post, $this->opt);
        $report = Report::build($postCtx, $this->catalog, (new Checker($post, $postCtx, $this->catalog))->run(), $this->opt, $post);
        $report['comparison'] = Verifier::compare($before, $report);
        Files::write($dir . '/report-after.json', Text::json($report), exclusive: true);
        $after = $report;
      } catch (Throwable $e) {
        $failed = true;
        $postError = Text::printable(strtok($e->getMessage(), "\n") ?: get_class($e));
      }
      try {
        $journal->data['finished_at'] = date(DATE_ATOM);
        $journal->data['failed'] = $failed;
        $journal->flush();
      } catch (Throwable) {
      }
      $completed = true;
    } finally {
      // Once the journal exists the protocol is written in every case, also when the run ends with an exception.
      $protocol = $this->protocol($journal, $plan, $before, $after, $postError, match (true) {
        !$completed => 'aborted',
        $failed || $after === null => 'failed',
        self::hasWarnings($journal) => 'warnings',
        default => 'ok',
      });
      // The exception's message follows from App; without this line the terminal would not say where the journal lies.
      if (!$completed) {
        Out::err('pg-harden: Lauf abgebrochen — Journal ' . Text::printable($dir) . ($protocol !== null ? ', Protokoll ' . Text::printable($protocol) : '') . "\n");
      }
    }
    $comparison = $after !== null ? Verifier::renderText($after['comparison']) : "\nNachprüfung nicht möglich: $postError\n";
    Out::write("\nERGEBNIS\n" . self::summary($journal) . $comparison
      . "\nJOURNAL\n" . TextRenderer::field('  Verzeichnis', Text::printable($dir) . ' (Sicherungen, Berichte vorher/nachher, Protokoll)')
      . ($protocol !== null ? TextRenderer::field('  Protokoll', Text::printable($protocol) . ' (HTML, im Browser öffnen)') : '')
      . TextRenderer::field('  Rückgängig', 'php pg-harden.php rollback --dir=' . Text::printable($dir) . ' (gleiche Verbindung)')
      . TextRenderer::notices(null));
    return $failed || $after === null ? 2 : (Report::exitCode($after) === 1 ? 1 : (self::hasWarnings($journal) ? 3 : 0));
  }

  /** apply.html in the journal. Not being able to write it is reported, but changes neither the run nor its exit code. */
  private function protocol(Journal $journal, array $plan, array $before, ?array $after, ?string $postError, string $outcome): ?string
  {
    $file = $journal->dir . '/apply.html';
    try {
      [$confirm, $other] = self::skippedGroups($plan['skipped']);
      Files::write($file, HtmlRenderer::applyLog([
        'started_at' => (string) $journal->data['started_at'],
        'finished_at' => $journal->data['finished_at'] ?? null,
        'server' => (string) $journal->data['server'],
        'server_version' => (string) $journal->data['server_version'],
        'user' => (string) $journal->data['user'],
        'dir' => $journal->dir,
        'outcome' => $outcome,
        'plan' => $plan,
        'skipped_confirm' => $confirm,
        'skipped_other' => $other,
        'steps' => $journal->data['steps'],
        'files' => $journal->data['files'],
        'sql' => $journal->data['sql'],
        'before_counts' => $before['meta']['counts'],
        'after' => $after,
        'post_error' => $postError,
      ]), exclusive: true);
      return $file;
    } catch (Throwable $e) {
      Out::err('pg-harden: Protokoll ' . Text::printable($file) . ' nicht geschrieben: ' . Text::printable(strtok($e->getMessage(), "\n") ?: get_class($e)) . "\n");
      return null;
    }
  }

  /** @return array{0: list<string>, 1: list<array{0: string, 1: string}>} rules waiting for --include-confirm, other skipped rules with their reason */
  private static function skippedGroups(array $skipped): array
  {
    $confirm = [];
    $other = [];
    foreach ($skipped as $entry) {
      [$id, $why] = $entry;
      if (($entry[2] ?? null) === 'confirm') {
        $confirm[$id] = (string) $id;
      } else {
        $other[$id . "\0" . $why] = [(string) $id, (string) $why];
      }
    }
    return [array_values($confirm), array_values($other)];
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
    Out::err("\nDiese Änderungen jetzt ausführen? Zum Bestätigen \"ja\" eingeben: ");
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
        $plan['skipped'][] = [$r['id'], 'braucht Freigabe: --include-confirm=' . $r['id'], 'confirm'];
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
      $config = $confPath === null ? null : Fs::readServerFile($confPath);
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
    $col = fn(string $left, string $right) => '    ' . mb_str_pad($left, 44) . ' ' . $right . "\n";
    $out = "\nGEPLANTE ÄNDERUNGEN\n";
    if ($plan['conf'] === [] && $plan['hba'] === [] && $plan['sql'] === []) {
      $out .= "  keine\n";
    }
    if ($plan['conf'] !== []) {
      $out .= "  Parameter → conf.d/90-pg-harden.conf\n";
      foreach ($plan['conf'] as $a) {
        $out .= $col("{$a['name']} = '{$a['value']}'", $a['rule'] . ($a['restart'] ? ' (Neustart nötig, wird nicht ausgeführt)' : ''));
      }
    }
    foreach ($plan['notes'] as $note) {
      $out .= '    Hinweis: ' . TextRenderer::wrap($note, 13) . "\n";
    }
    if ($plan['hba'] !== []) {
      $out .= "  pg_hba.conf — Sicherung, Prüfung durch den Server, Anmeldetest nach dem Neuladen\n"
        . "    (der Test deckt nur die Anmeldung dieses Werkzeugs ab, nicht Anwendungen und andere Rollen)\n";
      foreach ($plan['hba'] as $a) {
        $out .= $col("Zeile {$a['line']}: " . ($a['kind'] === 'type' ? 'Typ' : 'Methode') . ' ' . implode('/', $a['from']) . " → {$a['to']}", $a['rule']);
      }
    }
    foreach ($plan['sql'] as $db => $items) {
      $out .= '  SQL in Datenbank ' . Text::printable((string) $db) . "\n";
      foreach ($items as $i) {
        $out .= '    ' . mb_str_pad($i['rule'], 29) . ' ' . TextRenderer::wrap(Text::printable($i['fix_sql']), 34) . "\n";
      }
    }
    if ($plan['skipped'] !== []) {
      [$confirm, $other] = self::skippedGroups($plan['skipped']);
      $out .= "\nNICHT AUSGEFÜHRT\n";
      if ($confirm !== []) {
        $out .= "  Brauchen eine Freigabe mit --include-confirm=<Kennung>:\n    " . TextRenderer::wrap(implode(', ', $confirm), 4) . "\n";
      }
      if ($other !== []) {
        $out .= $confirm !== [] ? "  Aus anderen Gründen:\n" : '';
        $ind = $confirm !== [] ? 4 : 2;
        foreach ($other as [$id, $why]) {
          $out .= str_repeat(' ', $ind) . mb_str_pad($id, 29) . ' ' . TextRenderer::wrap($why, $ind + 30) . "\n";
        }
      }
    }
    return $out;
  }

  private static function summary(Journal $j): string
  {
    $out = '';
    foreach ($j->data['steps'] as $s) {
      $out .= "  [{$s['status']}] " . TextRenderer::wrap($s['phase'] . ': ' . Text::printable($s['message']), 5 + mb_strlen($s['status'])) . "\n";
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
    // Windows: the server's directories are held from before the first read to the end of the file phase (WindowsPin, without
    // FILE_SHARE_DELETE/FILE_SHARE_WRITE, verified by the final path of each handle) — what is read and written then goes the held way.
    $pinRoots = $this->pinRoots = array_values(array_unique([$local->dataDir, dirname($confPath)]));
    try {
      WindowsPin::begin($pinRoots, array_values(array_filter([$plan['hba'] !== [] ? $hbaPath : null, $confPath])));
    } catch (Throwable $e) {
      $journal->step('Vorbereitung', 'FEHLER', (strtok($e->getMessage(), "\n") ?: get_class($e)) . ' — nichts geändert');
      return false;
    }
    try {
      return $this->applyHeldFiles($plan, $local, $journal, $files, $hbaPath, $confPath, $pinRoots);
    } finally {
      WindowsPin::end();
    }
  }

  /** applyFiles once the server's directories are held (WindowsPin; elsewhere a no-op). */
  private function applyHeldFiles(array $plan, LocalServer $local, Journal $journal, ServerFiles $files, string $hbaPath, string $confPath, array $pinRoots): bool
  {
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
    $config = Fs::readServerFile($confPath);
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
      // The include directory is known only now (from postgresql.conf): its way is held as well before anything is read there.
      $prelimTargets = array_values(array_filter([$plan['hba'] !== [] ? $hbaPath : null, $confPath, $plan['conf'] !== [] ? $includeDir : null]));
      WindowsPin::begin($pinRoots, $prelimTargets);
      $hbaNew = $plan['hba'] !== [] ? $this->editHba($hbaPath, $plan['hba'], $hbaRowsBefore, $local, $journal) : null;
      // The same content that $inside checked above: a second read could name a different include_dir.
      $confNew = $plan['conf'] !== [] ? $this->prepareConf($plan['conf'], $confPath, (string) $config) : null;
      // The identity for every target is settled now, before the first change: a refusal (a directory others can write,
      // an owner without an account) must not come halfway through the file phase.
      $targets = array_merge($hbaNew !== null ? [$hbaPath] : [], array_column($confNew['writes'] ?? [], 'path'), array_filter(array_column($confNew['writes'] ?? [], 'mkdir')));
      WindowsPin::begin($pinRoots, array_values(array_unique(array_merge($prelimTargets, $targets))));
      foreach ($targets as $target) {
        Fs::asOwnerOf($target, static fn() => null);
      }
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
    Guard::arm($journal, $files, $pinRoots);
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
        // A failed check after the operation (WindowsPin) carries the operation's own error as previous: both belong in the journal.
        $previous = $e->getPrevious();
        return $this->fail($files, $journal, 'Schreiben', $e->getMessage() . ($previous !== null ? ' (zuvor: ' . (strtok($previous->getMessage(), "\n") ?: get_class($previous)) . ')' : ''));
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
      WindowsPin::end();
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
        Out::err('pg-harden: ' . Text::printable("$p [$status] $m") . "\n");
      }
    };
    $problems = [];
    try {
      $problems = ServerFiles::restore($journal->data['files'], $journal->dir, $this->pinRoots);
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
    $content = Fs::readServerFile($path);
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
  private function prepareConf(array $settings, string $confPath, string $config): array
  {
    $writes = [];
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
    // apply creates one directory, never a chain: the server reports a missing include_dir anyway, this keeps it explicit.
    if ($mkdir !== null && Fs::attempt(fn() => is_dir(dirname($mkdir))) !== true) {
      throw new HardenException('Das Include-Verzeichnis ' . Text::printable($mkdir) . ' hat kein vorhandenes Elternverzeichnis — apply legt nur eine Ebene an.');
    }
    $target = $includeDir . '/90-pg-harden.conf';
    $existing = Fs::readServerFile($target);
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
          Out::err("pg-harden: Journal nicht beschreibbar — Zustand von Datenbank $db prüfen.\n");
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
      // Same requirement as apply: without pcntl a closed output or a signal could end the process between "restored" and "reloaded",
      // without posix root would write as root instead of as the file's owner (Windows has neither SIGPIPE nor an identity switch).
      if (!Platform::windows() && (!function_exists('pcntl_signal') || !function_exists('posix_seteuid'))) {
        throw new HardenException('rollback mit Dateien braucht die PHP-Erweiterungen pcntl und posix (Schutz bei Abbruch und Identitätswechsel als root) — nichts geändert.');
      }
      $allowed = ServerFiles::allowedTargets($ctx->local);
      foreach ($data['files'] as $f) {
        if (!in_array(ServerFiles::norm($f['path']), $allowed, true)) {
          throw new HardenException('Das Journal nennt einen Pfad, den apply auf diesem Server nie schreiben würde: ' . Text::printable($f['path']) . ' — nichts geändert.');
        }
      }
    }
    // Restoring and reloading must not be cut short by Ctrl+C, Ctrl+\, a closed terminal or a stopped service; once set, this lasts
    // to the end, the SQL way back included. Without files nothing is set: the SQL way back alone runs in one transaction per
    // database. SIGKILL cannot be caught — the same command repeats the rollback.
    if ($data['files'] !== []) {
      if (function_exists('pcntl_signal')) {
        foreach ([SIGINT, SIGTERM, SIGHUP, SIGQUIT] as $signal) {
          pcntl_signal($signal, SIG_IGN);
        }
      } elseif (function_exists('sapi_windows_set_ctrl_handler')) {
        sapi_windows_set_ctrl_handler(fn() => true);
      }
    }
    $log = ['started_at' => date(DATE_ATOM), 'steps' => []];
    Out::write('pg-harden ' . PG_HARDEN_VERSION . ' · rollback · ' . TextRenderer::when($log['started_at']) . "\n"
      . TextRenderer::field('Server', Text::printable($ctx->server) . ' · PostgreSQL ' . Text::printable($ctx->version) . ' · Benutzer ' . Text::printable($ctx->user))
      . TextRenderer::field('Journal', Text::printable($dir) . ' (apply vom ' . TextRenderer::when((string) ($data['started_at'] ?? '')) . ')') . "\nSCHRITTE\n");
    $step = function (string $status, string $message) use (&$log): void {
      $log['steps'][] = ['status' => $status, 'message' => $message];
      Out::write("  [$status] " . Text::printable($message) . "\n");
    };
    $ok = true;
    if ($data['files'] !== []) {
      $confPath = $ctx->local->path('config_file');
      $pinRoots = array_values(array_unique(array_filter([$ctx->local->dataDir, $confPath === null ? null : dirname($confPath)])));
      $problems = [];
      try {
        // restore() holds the server's directories itself (WindowsPin) and rebuilds the hold if the helper ends in between.
        $problems = ServerFiles::restore($data['files'], $dir, $pinRoots);
      } catch (Throwable $e) {
        $problems[] = strtok($e->getMessage(), "\n") ?: get_class($e);
      } finally {
        WindowsPin::end();
      }
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
    $attempt = 'rollback-attempt-' . date('Ymd-His');
    $logName = $ok ? 'rollback-log.json' : "$attempt.json";
    Files::write("$dir/$logName", Text::json($log), exclusive: true);
    $protocol = self::protocol($ok ? "$dir/rollback.html" : "$dir/$attempt.html", $log + [
      'server' => $ctx->server,
      'server_version' => $ctx->version,
      'user' => $ctx->user,
      'dir' => $dir,
      'apply_started_at' => (string) ($data['started_at'] ?? ''),
      'log_file' => $logName,
    ]);
    Out::write("\nRückweg " . ($ok ? 'abgeschlossen' : 'unvollständig — Journal prüfen') . ".\n"
      . ($protocol !== null ? TextRenderer::field('Protokoll', Text::printable($protocol) . ' (HTML, im Browser öffnen)') : '')
      . TextRenderer::notices(null));
    return $ok ? 0 : 2;
  }

  /** The HTML protocol next to the rollback log. Not being able to write it is reported, but changes neither the run nor its exit code. */
  private static function protocol(string $file, array $log): ?string
  {
    try {
      Files::write($file, HtmlRenderer::rollbackLog($log), exclusive: true);
      return $file;
    } catch (Throwable $e) {
      Out::err('pg-harden: Protokoll ' . Text::printable($file) . ' nicht geschrieben: ' . Text::printable(strtok($e->getMessage(), "\n") ?: get_class($e)) . "\n");
      return null;
    }
  }
}
