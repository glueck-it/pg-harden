<?php
declare(strict_types=1);

// Lab test for Fs::writerFor / Fs::asOwnerOf: the identity root takes on before it writes below a directory of the service account.
// Usage (as root, in a throw-away container with a "postgres" account): PGHARDEN_LAB=1 php tests/lab-identity.php
// Builds its own directories under /opt/pgh-identity and a probe target in /etc; prints one line per case, exit 1 on any failure.

if (getenv('PGHARDEN_LAB') !== '1') {
  fwrite(STDERR, "Nur in einem Wegwerf-Container: PGHARDEN_LAB=1 setzen (das Skript legt Verzeichnisse und Links als root an).\n");
  exit(2);
}
define('PG_HARDEN_LIBRARY', true);
require __DIR__ . '/../pg-harden.php';
// As in App::main: warnings become exceptions, which Fs::attempt turns into "not possible"
set_error_handler(fn(int $no, string $msg, string $file, int $line): bool => throw new ErrorException($msg, 0, $no, $file, $line));

if (!function_exists('posix_geteuid') || posix_geteuid() !== 0 || ($svc = posix_getpwnam('postgres')) === false) {
  fwrite(STDERR, "Braucht root, posix und ein Konto postgres.\n");
  exit(2);
}
$base = '/opt/pgh-identity-' . bin2hex(random_bytes(3));
$probe = '/etc/pgh-identity-probe-' . bin2hex(random_bytes(3));
mkdir("$base/root-only", 0755, true);
mkdir("$base/svc", 0700);
chown("$base/svc", $svc['uid']);
chgrp("$base/svc", $svc['gid']);
mkdir("$base/open", 0777);
chmod("$base/open", 0777);
// What the service account can do to the way at any time: a link from its own directory to a directory of root
symlink('/etc', "$base/svc/link");
lchown("$base/svc/link", $svc['uid']);
// A link root placed in a root-only directory is trusted and followed
symlink("$base/svc", "$base/root-only/rootlink");
file_put_contents("$base/root-only/root.conf", "x\n");
file_put_contents("$base/root-only/svc.conf", "x\n");
chown("$base/root-only/svc.conf", $svc['uid']);

$who = static fn(?array $id): string => $id === null ? 'root' : ($id['uid'] === $svc['uid'] ? 'postgres' : 'uid ' . $id['uid']);
$failed = 0;
$expect = static function (string $case, string $want, callable $fn) use (&$failed): void {
  try {
    $got = $fn();
  } catch (HardenException $e) {
    $got = 'abgewiesen';
  }
  $ok = $got === $want;
  $failed += $ok ? 0 : 1;
  echo ($ok ? 'OK    ' : 'FEHLER') . " $case: $got" . ($ok ? '' : " (erwartet: $want)") . "\n";
};

$expect('neue Datei in einem Verzeichnis nur für root', 'root', fn() => $who(Fs::writerFor("$base/root-only/new.conf")));
$expect('vorhandene Datei von root dort', 'root', fn() => $who(Fs::writerFor("$base/root-only/root.conf")));
$expect('vorhandene Datei des Dienstkontos dort', 'postgres', fn() => $who(Fs::writerFor("$base/root-only/svc.conf")));
$expect('neue Datei im Verzeichnis des Dienstkontos', 'postgres', fn() => $who(Fs::writerFor("$base/svc/new.conf")));
$expect('Link des Dienstkontos nach /etc', 'postgres', fn() => $who(Fs::writerFor("$base/svc/link/" . basename($probe))));
$expect('Link von root in dessen Verzeichnis, weiter in das Dienstkonto', 'postgres', fn() => $who(Fs::writerFor("$base/root-only/rootlink/new.conf")));
$expect('Verzeichnis für alle beschreibbar', 'abgewiesen', fn() => $who(Fs::writerFor("$base/open/new.conf")));
// svc could be swapped for a link at any time, then ".." leads elsewhere: the way stays the service account's
$expect('.. hinter dem Verzeichnis des Dienstkontos', 'postgres', fn() => $who(Fs::writerFor("$base/svc/../root-only/new.conf")));

// The attack the rule closes: create() as root through the service account's link must not reach /etc
$expect('create() durch den Link nach /etc', 'abgewiesen', function () use ($base, $probe): string {
  ServerFiles::create("$base/svc/link/" . basename($probe), "probe\n", "$base/root-only/root.conf");
  return 'angelegt';
});
$expect('Probedatei in /etc', 'fehlt', fn() => file_exists($probe) ? 'vorhanden' : 'fehlt');

// The identity is the account with its own groups: neither root's supplementary group list nor the group of a directory "postgres:root"
mkdir("$base/svc-rootgroup", 0700);
chown("$base/svc-rootgroup", $svc['uid']);
chgrp("$base/svc-rootgroup", 0);
$groups = static fn(): string => posix_getegid() === 0 || in_array(0, posix_getgroups(), true) ? 'mit Gruppe root' : 'ohne Gruppe root';
$expect('Gruppen als Dienstkonto', 'ohne Gruppe root', fn() => Fs::asOwnerOf("$base/svc/new.conf", $groups));
$expect('Gruppen als Dienstkonto unter "postgres:root"', 'ohne Gruppe root', fn() => Fs::asOwnerOf("$base/svc-rootgroup/new.conf", $groups));
$expect('Gruppen danach wieder', 'mit Gruppe root', $groups);

// A file of root in the service account's directory: written in place (owner and group stay), or refused with the account named
file_put_contents("$base/svc/shared.conf", "alt\n");
chgrp("$base/svc/shared.conf", $svc['gid']);
chmod("$base/svc/shared.conf", 0660);
$expect('root-eigene, für das Dienstkonto beschreibbare Datei', 'neu, Besitzer root', function () use ($base): string {
  ServerFiles::overwrite("$base/svc/shared.conf", "neu\n");
  clearstatcache();
  return trim((string) file_get_contents("$base/svc/shared.conf")) . ', Besitzer ' . (fileowner("$base/svc/shared.conf") === 0 ? 'root' : 'nicht root');
});
file_put_contents("$base/svc/rootonly.conf", "alt\n");
chmod("$base/svc/rootonly.conf", 0644);
$expect('root-eigene, für das Dienstkonto schreibgeschützte Datei', 'abgewiesen mit Konto', function () use ($base): string {
  try {
    ServerFiles::overwrite("$base/svc/rootonly.conf", "neu\n");
    return 'überschrieben';
  } catch (HardenException $e) {
    return str_contains($e->getMessage(), 'als Konto postgres') ? 'abgewiesen mit Konto' : 'abgewiesen ohne Konto: ' . $e->getMessage();
  }
});
$expect('Identität nach den Dateifällen', 'root', fn() => posix_geteuid() === 0 && posix_getegid() === 0 ? 'root' : 'uid ' . posix_geteuid());

// Reading (check, client): the same walk, but a directory others may write to hands the decision on instead of refusing
mkdir("$base/sticky", 0777);
chmod("$base/sticky", 01777);
mkdir("$base/sticky/svc-dir", 0700);
chown("$base/sticky/svc-dir", $svc['uid']);
mkdir("$base/sticky/root-dir", 0755);
file_put_contents("$base/sticky/root.conf", "x\n");
$whoRead = static fn(?array $id): string => $id === null ? 'root' : ($id['uid'] === $svc['uid'] ? 'postgres' : $id['name']);
$expect('Lesen: Datei in einem Verzeichnis nur für root', 'root', fn() => $whoRead(Fs::readerFor("$base/root-only/root.conf")));
$expect('Lesen: Link des Dienstkontos nach /etc', 'postgres', fn() => $whoRead(Fs::readerFor("$base/svc/link/passwd")));
$expect('Lesen: Verzeichnis für alle beschreibbar, ohne Sticky-Bit', 'nobody', fn() => $whoRead(Fs::readerFor("$base/open/x.conf")));
$expect('Lesen: Sticky-Verzeichnis, Eintrag des Dienstkontos', 'postgres', fn() => $whoRead(Fs::readerFor("$base/sticky/svc-dir/x.conf")));
$expect('Lesen: Sticky-Verzeichnis, Verzeichnis von root', 'root', fn() => $whoRead(Fs::readerFor("$base/sticky/root-dir/x.conf")));
$expect('Lesen: Sticky-Verzeichnis, Datei von root (Name könnte fremd gewählt sein)', 'nobody', fn() => $whoRead(Fs::readerFor("$base/sticky/root.conf")));
$expect('Lesen: Sticky-Verzeichnis, fehlender Eintrag', 'nobody', fn() => $whoRead(Fs::readerFor("$base/sticky/fehlt.conf")));
link("$base/root-only/root.conf", "$base/sticky/hardlink.conf");
$expect('Lesen: Sticky-Verzeichnis, zweiter Name einer Datei von root', 'nobody', fn() => $whoRead(Fs::readerFor("$base/sticky/hardlink.conf")));
$expect('Lesen: relativer Pfad zählt ab dem Arbeitsverzeichnis', 'gelesen', function () use ($base): string {
  chdir("$base/root-only");
  return Fs::readGuarded('root.conf') === "x\n" ? 'gelesen' : 'nicht gelesen';
});
chdir('/');
$expect('Schreiben: Sticky-Verzeichnis bleibt abgewiesen', 'abgewiesen', fn() => $whoRead(Fs::writerFor("$base/sticky/svc-dir/x.conf")));

// The attack: a person's .pgpass (or postmaster.pid) as a link to a file only root may read
file_put_contents("$base/root-only/secret", "geheim\n");
chmod("$base/root-only/secret", 0600);
symlink("$base/root-only/secret", "$base/svc/pgpass");
lchown("$base/svc/pgpass", $svc['uid']);
$expect('readGuarded durch den Link auf eine Datei von root', 'nicht gelesen', fn() => Fs::readGuarded("$base/svc/pgpass") === null ? 'nicht gelesen' : 'gelesen');
$expect('readGuarded einer Datei des Dienstkontos', 'gelesen', function () use ($base, $svc): string {
  file_put_contents("$base/svc/own.conf", "x\n");
  chown("$base/svc/own.conf", $svc['uid']);
  chmod("$base/svc/own.conf", 0600);
  return Fs::readGuarded("$base/svc/own.conf") === "x\n" ? 'gelesen' : 'nicht gelesen';
});

// A FIFO or device in place of a file: refused at once instead of hanging in open() or reading without end
posix_mkfifo("$base/svc/fifo", 0600);
$expect('read() einer FIFO', 'abgewiesen ohne Warten', function () use ($base): string {
  $t = microtime(true);
  $got = Fs::read("$base/svc/fifo");
  return $got === null && microtime(true) - $t < 2 ? 'abgewiesen ohne Warten' : 'gelesen oder gewartet';
});
$expect('read() eines Geräts', 'abgewiesen', fn() => Fs::read('/dev/zero') === null ? 'abgewiesen' : 'gelesen');
$expect('read() über der Grenze', 'abgewiesen', fn() => Fs::read("$base/root-only/root.conf", 1) === null ? 'abgewiesen' : 'gelesen');
$expect('read() aus /proc (Größe 0)', 'gelesen', fn() => str_contains((string) Fs::read('/proc/self/status', 65536), 'PPid:') ? 'gelesen' : 'nicht gelesen');
$expect('Identität nach den Lesefällen', 'root', fn() => posix_geteuid() === 0 && posix_getegid() === 0 ? 'root' : 'uid ' . posix_geteuid());

// Clean up (as root; the probe file only exists after a regression)
$remove = static function (string $p) use (&$remove): void {
  if (is_dir($p) && !is_link($p)) {
    foreach (array_diff(scandir($p) ?: [], ['.', '..']) as $e) {
      $remove("$p/$e");
    }
    rmdir($p);
  } elseif (file_exists($p) || is_link($p)) {
    unlink($p);
  }
};
$remove($base);
$remove($probe);
$expect('Identität nach dem Lauf', 'root', fn() => posix_geteuid() === 0 && posix_getegid() === 0 ? 'root' : 'uid ' . posix_geteuid());
exit($failed === 0 ? 0 : 1);
