<?php
declare(strict_types=1);

// Windows test for Fs::windowsRedirected / Fs::readGuarded with a profile root: what client --user reads below another
// account's profile must not lead elsewhere through a junction. Needs no administrator rights (junctions do not).
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
