<?php
declare(strict_types=1);

// Windows test for Fs::windowsRedirected / Fs::readGuarded, handle-based ACL reading (WindowsFacts, ClientProbes) and
// race-free directory pinning (WindowsPin, ServerFiles, Journal): what check, client --user, apply and rollback read or write
// below another account's profile or the server's data directory must not lead elsewhere through a junction, and pinned
// target directories cannot be renamed or removed while held. Needs no administrator rights (junctions do not).
// Usage: php tests/windows-redirect.php — builds its own directories in the temp directory, removes them afterwards,
// prints one line per case, exit 1 on any failure.

define('PG_HARDEN_LIBRARY', true);
require __DIR__ . '/../pg-harden.php';
// As in App::main: warnings become exceptions, which Fs::attempt turns into "not possible"
set_error_handler(fn(int $no, string $msg, string $file, int $line): bool => throw new ErrorException($msg, 0, $no, $file, $line));

if (!Platform::windows()) {
  fwrite(STDERR, "Nur unter Windows.\n");
  exit(2);
}
$root = sys_get_temp_dir() . '\\pgh-redirect-' . bin2hex(random_bytes(3));
$profile = "$root\\Profile";
$elsewhere = "$root\\Other";
$own = "$profile\\AppData\\Roaming\\postgresql\\pgpass.conf";
mkdir(dirname($own), 0777, true);
mkdir("$profile\\Documents", 0777, true);
mkdir("$profile\\Swap", 0777, true);
mkdir($elsewhere, 0777, true);
file_put_contents($own, "own\n");
file_put_contents("$profile\\Swap\\pgpass.conf", "own\n");
file_put_contents("$elsewhere\\pgpass.conf", "other\n");
file_put_contents("$elsewhere\\profile.ps1", "other\n");
// A hit for the file search, once behind the junction (must stay unread) and once in a plain directory of the profile (must be found)
file_put_contents("$elsewhere\\deploy.ps1", "PGPASSWORD=x\n");
mkdir("$profile\\Scripts", 0777, true);
file_put_contents("$profile\\Scripts\\deploy.ps1", "PGPASSWORD=x\n");

/** @var string[] every junction this test made — removed as links before the tree, so no walk can enter one */
$links = [];
$dropLink = static function (string $link): void {
  // A non-recursive delete of a junction removes the link itself, never its target.
  if (Fs::attempt(fn() => rmdir($link)) === null) {
    try {
      Platform::powershell("[IO.Directory]::Delete(\$d.link)\nConvertTo-Json -InputObject @{ ok = \$true } -Compress", ['link' => $link]);
    } catch (Throwable) {
      // Left for the final check, which then fails.
    }
  }
};
// Removes the tree. Only what PHP reports as a directory and not a link is entered; PHP reports a junction as neither a link nor a
// directory, so one the list above missed is only removed as a link (never entered, its target stays untouched).
$remove = static function (string $p) use (&$remove, $dropLink): void {
  if (is_dir($p) && !is_link($p)) {
    foreach (array_diff(scandir($p) ?: [], ['.', '..']) as $e) {
      $remove("$p\\$e");
    }
    Fs::attempt(fn() => rmdir($p));
  } elseif (is_file($p) || is_link($p)) {
    Fs::attempt(fn() => unlink($p));
  } else {
    $dropLink($p);
  }
};
// What the examined account can do in its own profile without any privilege: a junction to a directory elsewhere
$junction = static function (string $link, string $target) use (&$links): bool {
  $out = [];
  exec('cmd /c mklink /J "' . $link . '" "' . $target . '" 2>nul', $out, $code);
  if ($code === 0) {
    $links[] = $link;
  }
  return $code === 0;
};

$failed = 0;
$expect = static function (string $case, string $want, callable $fn) use (&$failed): void {
  try {
    $got = $fn();
  } catch (Throwable $e) {
    $got = 'Ausnahme: ' . $e->getMessage();
  }
  $ok = $got === $want;
  $failed += $ok ? 0 : 1;
  echo ($ok ? 'OK    ' : 'FEHLER') . " $case: $got" . ($ok ? '' : " (erwartet: $want)") . "\n";
};
$redir = static fn(string $path, string $base): string => Fs::windowsRedirected($path, $base) ? 'umgeleitet' : 'direkt';
$read = static fn(?string $content): string => $content === null ? 'nicht gelesen' : 'gelesen: ' . trim($content);

try {
  $ps = "$profile\\Documents\\WindowsPowerShell";
  if (!$junction($ps, $elsewhere)) {
    throw new RuntimeException('Junction ließ sich nicht anlegen.');
  }
  $short = trim((string) shell_exec('cmd /c for %I in ("' . $profile . '") do @echo %~sI'));

  $expect('eigene Datei im Profil', 'direkt', fn() => $redir($own, $profile));
  $expect('Datei hinter einer Junction des Kontos', 'umgeleitet', fn() => $redir("$ps\\profile.ps1", $profile));
  $expect('Profilwurzel in anderer Schreibweise', 'direkt', fn() => $redir(strtoupper($own), $profile));
  $expect('Schrägstrich als Trenner', 'direkt', fn() => $redir(str_replace('\\', '/', $own), $profile));
  $expect('Junction, ganzer Pfad mit Schrägstrichen', 'umgeleitet', fn() => $redir(str_replace('\\', '/', "$ps\\profile.ps1"), $profile));
  $expect('Junction, Präfix \\\\?\\', 'umgeleitet', fn() => $redir("\\\\?\\$ps\\profile.ps1", $profile));
  $expect('eigene Datei, Präfix \\\\?\\', 'direkt', fn() => $redir("\\\\?\\$own", $profile));
  if ($short === '' || strcasecmp($short, $profile) === 0) {
    echo "--     Kurzname des Profils: übersprungen (keine 8.3-Namen auf diesem Laufwerk)\n";
  } else {
    $expect('Kurzname des Profils (nicht zuzuordnen)', 'umgeleitet', fn() => $redir("$short\\AppData\\Roaming\\postgresql\\pgpass.conf", $profile));
  }
  $expect('.. im Weg', 'umgeleitet', fn() => $redir("$profile\\Documents\\..\\..\\Other\\pgpass.conf", $profile));
  $expect('fehlende Datei (nicht prüfbar)', 'umgeleitet', fn() => $redir("$profile\\Documents\\fehlt.txt", $profile));
  $expect('Pfad außerhalb des Profils (nicht beurteilt)', 'direkt', fn() => $redir("$elsewhere\\pgpass.conf", $profile));
  $expect('Name, der nur mit dem Profilnamen beginnt (nicht beurteilt)', 'direkt', fn() => $redir("{$profile}2\\x.txt", $profile));

  // A junction whose target is a volume GUID path: PHP's realpath does not resolve it, the final path of the handle does.
  $guid = '';
  foreach (explode("\n", (string) shell_exec('mountvol ' . substr($root, 0, 2) . '\\ /L')) as $line) {
    $guid = str_starts_with(trim($line), '\\\\?\\Volume{') ? rtrim(trim($line), '\\') : $guid;
  }
  $volumeLink = "$profile\\Documents\\Vol";
  $expect('Junction auf Volume-GUID-Pfad', 'umgeleitet', fn() => $guid !== '' && $junction($volumeLink, $guid . substr($elsewhere, 2))
    ? $redir("$volumeLink\\pgpass.conf", $profile) : 'nicht anlegbar');
  $expect('readGuarded: hinter der Volume-Junction', 'nicht gelesen', fn() => $read(Fs::readGuarded("$volumeLink\\pgpass.conf", 4096, $profile)));

  // Checked once (PHP's realpath cache is filled), then the account swaps the directory for a junction.
  $swapped = "$profile\\Swap\\pgpass.conf";
  $expect('vor dem Tausch', 'gelesen: own', fn() => $read(Fs::readGuarded($swapped, 4096, $profile)));
  unlink($swapped);
  rmdir("$profile\\Swap");
  $expect('Tausch gegen eine Junction', 'ja', fn() => $junction("$profile\\Swap", $elsewhere) ? 'ja' : 'nein');
  $expect('nach dem Tausch: windowsRedirected', 'umgeleitet', fn() => $redir($swapped, $profile));
  $expect('nach dem Tausch: readGuarded', 'nicht gelesen', fn() => $read(Fs::readGuarded($swapped, 4096, $profile)));

  $expect('readGuarded: eigene Datei', 'gelesen: own', fn() => $read(Fs::readGuarded($own, 4096, $profile)));
  $expect('readGuarded: hinter der Junction', 'nicht gelesen', fn() => $read(Fs::readGuarded("$ps\\profile.ps1", 4096, $profile)));
  $expect('readGuarded ohne Profil (eigenes Konto): liest', 'gelesen: other', fn() => $read(Fs::readGuarded("$ps\\profile.ps1", 4096)));

  $scan = new SecretScan($profile);
  $expect('Suche: Datei hinter der Junction wird nicht gelesen', 'übersprungen', function () use ($scan, $ps): string {
    $scan->file("$ps\\profile.ps1");
    return array_filter($scan->skipped, fn($s) => str_contains($s, ClientProbes::REDIRECTED)) !== [] ? 'übersprungen' : 'gelesen';
  });
  $tree = array_keys((new SecretScan($profile))->tree($profile));
  $expect('Suche über das Profil: Fund im eigenen Ordner', 'ja', fn() => in_array("$profile\\Scripts\\deploy.ps1", $tree, true) ? 'ja' : 'nein');
  $expect('Suche über das Profil: nichts hinter einer Junction', 'nein', fn() => array_filter($tree, fn($p) => stripos($p, 'Scripts') === false) !== [] ? 'ja: ' . implode(', ', $tree) : 'nein');

  // ── ACL over the opened handle (GetSecurityInfo + GetFinalPathNameByHandle) ──
  $expect('strictAcl über Handle: eigene Datei', 'gelesen', fn() => is_array($a = WindowsFacts::strictAcl($own, $profile)) && $a['owner'] !== '' ? 'gelesen' : 'leer');
  $expect('strictAcl über Handle: hinter der Junction', 'abgewiesen', fn() => WindowsFacts::strictAcl("$ps\\profile.ps1", $profile) === null ? 'abgewiesen' : 'gelesen');
  $expect('strictAcl über Handle: hinter der Volume-Junction', 'abgewiesen', fn() => WindowsFacts::strictAcl("$volumeLink\\pgpass.conf", $profile) === null ? 'abgewiesen' : 'gelesen');
  $expect('broadAcesOf über Handle: eigene Datei', 'gelesen', fn() => is_array(WindowsFacts::broadAcesOf($own, $profile)) ? 'gelesen' : 'leer');
  $expect('broadAcesOf über Handle: hinter der Junction', 'abgewiesen', fn() => WindowsFacts::broadAcesOf("$ps\\profile.ps1", $profile) === null ? 'abgewiesen' : 'gelesen');

  $ctxDirect = new ClientContext('foreign', $profile, "$profile\\AppData\\Roaming", false, null, []);
  $aclDirect = ClientProbes::run('pgpass_acl', $ctxDirect);
  $expect('ClientProbes pgpass_acl (direkt im Profil): geprüft', 'geprüft', fn() => $aclDirect['unchecked'] === [] ? 'geprüft' : 'nicht geprüft: ' . implode(', ', $aclDirect['unchecked']));

  file_put_contents("$profile\\AppData\\Roaming\\postgresql\\psql_history", "SELECT 1;\nALTER ROLE app WITH PASSWORD 'secret';\n");
  $histDirect = ClientProbes::run('psql_history', $ctxDirect);
  $expect('ClientProbes psql_history erkennt Passwort in Historie', 'erkannt',
    fn() => array_filter($histDirect['findings'], fn($f) => str_contains($f['detail'], 'CREATE/ALTER ROLE')) !== [] ? 'erkannt' : 'übersehen');

  $juncAppData = "$profile\\JuncAppData";
  mkdir($juncAppData, 0777, true);
  $expect('Junction für postgresql-Ordner im Profil', 'ja', fn() => $junction("$juncAppData\\postgresql", $elsewhere) ? 'ja' : 'nein');
  $ctxRedirected = new ClientContext('foreign', $profile, $juncAppData, false, null, []);
  $aclRedirected = ClientProbes::run('pgpass_acl', $ctxRedirected);
  $expect('ClientProbes pgpass_acl (hinter Junction): nicht geprüft', 'abgewiesen',
    fn() => $aclRedirected['findings'] === [] && array_filter($aclRedirected['unchecked'], fn($u) => str_contains($u, ClientProbes::REDIRECTED)) !== [] ? 'abgewiesen' : 'durchgelassen');
  file_put_contents("$elsewhere\\psql_history", "ALTER ROLE postgres WITH PASSWORD 'topsecret';\n");
  $histRedirected = ClientProbes::run('psql_history', $ctxRedirected);
  $expect('ClientProbes psql_history (hinter Junction): nicht gelesen', 'abgewiesen',
    fn() => $histRedirected['findings'] === [] && array_filter($histRedirected['unchecked'], fn($u) => str_contains($u, ClientProbes::REDIRECTED)) !== [] ? 'abgewiesen' : 'durchgelassen');

  // ── LocalServer + WindowsFacts::aces (check) ─────────────────────────────
  $dataDir = "$root\\Data";
  mkdir($dataDir, 0777, true);
  file_put_contents("$dataDir\\postgresql.conf", "# base\n");
  file_put_contents("$dataDir\\postmaster.pid", "1234\n$dataDir\n1700000000\n5432\n");
  $expect('postmaster.pid im Datenverzeichnis (direkt): lesbar', 'gelesen',
    fn() => Fs::readGuarded("$dataDir\\postmaster.pid", 4096, $dataDir) !== null ? 'gelesen' : 'abgewiesen');
  $expect('Junction im Datenverzeichnis', 'ja', fn() => $junction("$dataDir\\redir", $elsewhere) ? 'ja' : 'nein');
  $expect('postmaster.pid hinter Junction im Datenverzeichnis: abgewiesen', 'abgewiesen',
    fn() => Fs::readGuarded("$dataDir\\redir\\pgpass.conf", 4096, $dataDir) === null ? 'abgewiesen' : 'gelesen');
  // The constructor stays private (only LocalServer::detect proves where a server runs): the test builds one inside the class scope.
  $srv = Closure::bind(fn() => new LocalServer(null, getmypid(), $dataDir, [
    'data_directory' => $dataDir,
    'config_file' => "$dataDir\\postgresql.conf",
    'hba_file' => "$dataDir\\redir\\pgpass.conf",
  ]), null, LocalServer::class)();
  $expect('WindowsFacts::aces über Handle (direkt)', 'gelesen', fn() => is_array(WindowsFacts::aces($srv, "$dataDir\\postgresql.conf")) ? 'gelesen' : 'abgewiesen');
  $expect('WindowsFacts::aces über Handle (hinter Junction)', 'abgewiesen', fn() => WindowsFacts::aces($srv, "$dataDir\\redir\\pgpass.conf") === null ? 'abgewiesen' : 'gelesen');

  // ── WindowsPin + ServerFiles + Journal (apply/rollback) ──────────────────
  $journalDir = "$root\\Journal";
  Files::prepareDir($journalDir);
  $journal = new Journal($journalDir, ['tool' => 'test']);

  WindowsPin::begin([$dataDir], ["$dataDir\\postgresql.conf", "$dataDir\\conf.d\\90-pg-harden.conf"]);
  $expect('WindowsPin: festgehaltenes Datenverzeichnis nicht umbenennbar', 'gesperrt',
    fn() => Fs::attempt(fn() => rename($dataDir, "$root\\DataMoved")) === null ? 'gesperrt' : 'umbenannt');
  $expect('WindowsPin: festgehaltenes Datenverzeichnis nicht löschbar', 'gesperrt',
    fn() => Fs::attempt(fn() => rmdir($dataDir)) === null ? 'gesperrt' : 'gelöscht');

  ServerFiles::makeDir("$dataDir\\conf.d", $dataDir);
  $expect('ServerFiles::makeDir hält neues Unterverzeichnis sofort fest', 'gesperrt',
    fn() => Fs::attempt(fn() => rename("$dataDir\\conf.d", "$dataDir\\conf.d.moved")) === null ? 'gesperrt' : 'umbenannt');
  $expect('Elternverzeichnis bleibt während pinCreatedDir durchgehend gesperrt', 'gesperrt',
    fn() => Fs::attempt(fn() => rename($dataDir, "$root\\DataMoved")) === null ? 'gesperrt' : 'umbenannt');

  ServerFiles::create("$dataDir\\conf.d\\90-pg-harden.conf", "ssl = on\n", "$dataDir\\postgresql.conf");
  $backupName = $journal->backup("$dataDir\\postgresql.conf");
  ServerFiles::overwrite("$dataDir\\postgresql.conf", "# gehärtet\n");
  $expect('Schreiben und Sichern im festgehaltenen Verzeichnis', 'ok',
    fn() => $backupName !== null && trim((string) file_get_contents("$dataDir\\conf.d\\90-pg-harden.conf")) === 'ssl = on'
      && trim((string) file_get_contents("$dataDir\\postgresql.conf")) === '# gehärtet' ? 'ok' : 'fehlgeschlagen');

  $problems = ServerFiles::restore([
    ['path' => "$dataDir\\postgresql.conf", 'action' => 'modified', 'backup' => $backupName],
    ['path' => "$dataDir\\conf.d", 'action' => 'created', 'backup' => null],
    ['path' => "$dataDir\\conf.d\\90-pg-harden.conf", 'action' => 'created', 'backup' => null],
  ], $journalDir);
  $expect('ServerFiles::restore spielt zurück und hält Datenverzeichnis weiter fest', 'ok',
    fn() => $problems === [] && !file_exists("$dataDir\\conf.d")
      && trim((string) file_get_contents("$dataDir\\postgresql.conf")) === '# base'
      && Fs::attempt(fn() => rename($dataDir, "$root\\DataMoved")) === null ? 'ok' : 'fehlgeschlagen: ' . implode(' | ', $problems));

  WindowsPin::end();
  $expect('Nach WindowsPin::end ist das Verzeichnis wieder frei', 'frei',
    fn() => Fs::attempt(fn() => rename($dataDir, "$root\\DataMoved")) === true && Fs::attempt(fn() => rename("$root\\DataMoved", $dataDir)) === true ? 'frei' : 'gesperrt');

  // Refusal when a directory on the way is a junction (fail-closed, target untouched):
  $expect('WindowsPin::begin weist Junction im Zielpfad ab', 'abgewiesen', function () use ($dataDir): string {
    try {
      WindowsPin::begin([$dataDir], ["$dataDir\\redir\\pgpass.conf"]);
      WindowsPin::end();
      return 'durchgelassen';
    } catch (HardenException) {
      return 'abgewiesen';
    }
  });
  // Without an active hold nothing is written (fail-closed), and a helper that died in between stops the next write as well.
  $expect('Ohne aktive Schreibsperre wird nicht geschrieben', 'abgewiesen', function () use ($dataDir): string {
    try {
      ServerFiles::overwrite("$dataDir\\postgresql.conf", "ohne Sperre\n");
      return 'durchgelassen';
    } catch (HardenException) {
      return trim((string) file_get_contents("$dataDir\\postgresql.conf")) === '# base' ? 'abgewiesen' : 'abgewiesen, aber Datei geändert';
    }
  });
  $expect('Beendeter Helfer: nächster Schreibvorgang abgewiesen', 'abgewiesen', function () use ($dataDir): string {
    WindowsPin::begin([$dataDir], ["$dataDir\\postgresql.conf"]);
    $proc = (new ReflectionProperty(WindowsPin::class, 'proc'))->getValue();
    proc_terminate($proc, 9);
    for ($i = 0; $i < 200 && proc_get_status($proc)['running']; $i++) {
      usleep(25000);
    }
    try {
      ServerFiles::overwrite("$dataDir\\postgresql.conf", "Helfer beendet\n");
      return 'durchgelassen';
    } catch (HardenException) {
      return trim((string) file_get_contents("$dataDir\\postgresql.conf")) === '# base' ? 'abgewiesen' : 'abgewiesen, aber Datei geändert';
    } finally {
      WindowsPin::end();
    }
  });
  // The server keeps working in its held data directory (ALTER SYSTEM and current_logfiles rename files there).
  $expect('Umbenennen im festgehaltenen Datenverzeichnis bleibt möglich', 'geht', function () use ($dataDir): string {
    WindowsPin::begin([$dataDir], ["$dataDir\\postgresql.conf"]);
    try {
      file_put_contents("$dataDir\\postgresql.auto.conf.tmp", "# auto\n");
      $ok = Fs::attempt(fn() => rename("$dataDir\\postgresql.auto.conf.tmp", "$dataDir\\postgresql.auto.conf")) === true;
      Fs::attempt(fn() => unlink("$dataDir\\postgresql.auto.conf"));
      return $ok ? 'geht' : 'gesperrt';
    } finally {
      WindowsPin::end();
    }
  });
  // A helper that ended in the middle of the file phase (Ctrl+C, crash): restore rebuilds the hold over the roots and restores.
  $expect('Wiederherstellung nach beendetem Helfer baut die Sperre neu auf', 'ok', function () use ($dataDir, $root): string {
    $journalDir = "$root\\RestoreJournal";
    $journal = new Journal($journalDir, ['tool' => 'test']);
    WindowsPin::begin([$dataDir], ["$dataDir\\postgresql.conf"]);
    $bak = $journal->backup("$dataDir\\postgresql.conf");
    ServerFiles::overwrite("$dataDir\\postgresql.conf", "# halb geschrieben\n");
    $proc = (new ReflectionProperty(WindowsPin::class, 'proc'))->getValue();
    proc_terminate($proc, 9);
    for ($i = 0; $i < 200 && proc_get_status($proc)['running']; $i++) {
      usleep(25000);
    }
    try {
      $problems = ServerFiles::restore([['path' => "$dataDir\\postgresql.conf", 'action' => 'modified', 'backup' => $bak]], $journalDir, [$dataDir]);
    } finally {
      WindowsPin::end();
    }
    return $problems === [] && trim((string) file_get_contents("$dataDir\\postgresql.conf")) === '# base' ? 'ok' : 'fehlgeschlagen: ' . implode(' | ', $problems);
  });
  // The cases below run under an active hold of the data directory: the refusal must come from the check of the way itself.
  WindowsPin::begin([$dataDir], ["$dataDir\\postgresql.conf"]);
  $expect('ServerFiles::overwrite weist Junction ab', 'abgewiesen', function () use ($dataDir): string {
    try {
      ServerFiles::overwrite("$dataDir\\redir\\pgpass.conf", "überschrieben\n");
      return 'durchgelassen';
    } catch (HardenException) {
      return 'abgewiesen';
    }
  });
  $expect('ServerFiles::create weist Junction ab', 'abgewiesen', function () use ($dataDir): string {
    try {
      ServerFiles::create("$dataDir\\redir\\neu.conf", "neu\n", "$dataDir\\postgresql.conf");
      return 'durchgelassen';
    } catch (HardenException) {
      return 'abgewiesen';
    }
  });
  $expect('Journal::backup weist Junction ab', 'abgewiesen', function () use ($journal, $dataDir): string {
    try {
      $journal->backup("$dataDir\\redir\\pgpass.conf");
      return 'durchgelassen';
    } catch (HardenException) {
      return 'abgewiesen';
    }
  });
  $restoreProblems = ServerFiles::restore([
    ['path' => "$dataDir\\redir\\pgpass.conf", 'action' => 'created', 'backup' => null],
  ], $journalDir);
  $expect('ServerFiles::restore weist Entfernen hinter einer Junction ab', 'abgewiesen',
    fn() => $restoreProblems !== [] && file_exists("$elsewhere\\pgpass.conf") ? 'abgewiesen' : 'durchgelassen');
  WindowsPin::end();

  // A run that ends in the middle of the file phase (Ctrl+C, fatal error): Guard::onShutdown restores under the hold that is still
  // active and releases it afterwards. The reload needs a server and fails here, which the handler only notes.
  $expect('Guard::onShutdown spielt nach Abbruch zurück und gibt die Sperre frei', 'ok', function () use ($dataDir, $root): string {
    $guardJournal = new Journal("$root\\GuardJournal", ['tool' => 'test']);
    WindowsPin::begin([$dataDir], ["$dataDir\\postgresql.conf"]);
    $guardJournal->file("$dataDir\\postgresql.conf", 'modified', $guardJournal->backup("$dataDir\\postgresql.conf"));
    ServerFiles::overwrite("$dataDir\\postgresql.conf", "# halb geschrieben\n");
    Guard::arm($guardJournal, (new ReflectionClass(ServerFiles::class))->newInstanceWithoutConstructor());
    Guard::onShutdown();
    $restored = trim((string) file_get_contents("$dataDir\\postgresql.conf")) === '# base';
    $released = Fs::attempt(fn() => rename($dataDir, "$root\\DataMoved")) === true && Fs::attempt(fn() => rename("$root\\DataMoved", $dataDir)) === true;
    return $restored && $released ? 'ok' : 'zurückgespielt: ' . ($restored ? 'ja' : 'nein') . ', frei: ' . ($released ? 'ja' : 'nein');
  });

  $expect('Journal-Verzeichnis hat nach Anlage enge ACL', 'ja',
    fn() => WindowsFacts::isStrictlyPrivate($journalDir) ? 'ja' : 'nein');
  $expect('Journal::load akzeptiert enges Journal-Verzeichnis', 'geladen',
    fn() => (Journal::load($journalDir)['journal_version'] ?? null) === Journal::VERSION ? 'geladen' : 'fehler');
  Platform::run([Platform::systemTool('icacls.exe'), $journalDir, '/grant', '*S-1-5-32-545:(OI)(CI)R']);
  $expect('Journal::load weist Journal-Verzeichnis mit fremdem ACE ab', 'abgewiesen', function () use ($journalDir): string {
    try {
      Journal::load($journalDir);
      return 'durchgelassen';
    } catch (HardenException) {
      return 'abgewiesen';
    }
  });
} catch (Throwable $e) {
  $failed++;
  echo 'FEHLER Aufbau: ' . $e->getMessage() . "\n";
} finally {
  foreach ($links as $link) {
    $dropLink($link);
  }
  $expect('Ziel hinter den Junctions unversehrt', 'ja', fn() => file_exists("$elsewhere\\pgpass.conf") && file_exists("$elsewhere\\profile.ps1") ? 'ja' : 'nein');
  $remove($root);
}
$expect('aufgeräumt', 'ja', fn() => file_exists($root) ? 'nein' : 'ja');
exit($failed === 0 ? 0 : 1);
