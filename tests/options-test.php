<?php
declare(strict_types=1);

/**
 * Offline test of the command line (Options::parse): long names, psql-style short options, values with "=" or as the next
 * argument, and the refusals. Runs without a PostgreSQL server: php tests/options-test.php
 */

define('PG_HARDEN_LIBRARY', true);
require_once dirname(__DIR__) . '/pg-harden.php';

$failed = 0;
$total = 0;
/** @param array<string, string> $want option => value (true as '1'), plus 'command' */
$parses = function (string $name, array $args, array $want) use (&$failed, &$total): void {
  $total++;
  try {
    $o = Options::parse(['pg-harden.php', ...$args]);
  } catch (HardenException $e) {
    $failed++;
    echo "FEHLER $name: abgewiesen ({$e->getMessage()})\n";
    return;
  }
  foreach ($want as $key => $value) {
    $got = $key === 'command' ? $o->command : $o->get($key);
    if ($got !== $value) {
      $failed++;
      echo "FEHLER $name: $key = " . var_export($got, true) . ' (erwartet ' . var_export($value, true) . ")\n";
      return;
    }
  }
};
$refuses = function (string $name, array $args, string $fragment) use (&$failed, &$total): void {
  $total++;
  try {
    Options::parse(['pg-harden.php', ...$args]);
    $failed++;
    echo "FEHLER $name: angenommen (erwartet Abweisung mit „{$fragment}“)\n";
  } catch (HardenException $e) {
    if (!str_contains($e->getMessage(), $fragment)) {
      $failed++;
      echo "FEHLER $name: Meldung „{$e->getMessage()}“ (erwartet „{$fragment}“)\n";
    }
  }
};

// Bisherige Schreibweise bleibt gültig
$parses('lange Namen mit =', ['check', '--host=db1', '--port=5433', '--user=postgres', '--dbname=app'],
  ['command' => 'check', 'host' => 'db1', 'port' => '5433', 'user' => 'postgres', 'dbname' => 'app']);
$parses('Schalter', ['apply', '--execute', '--yes', '--dir=x'], ['execute' => '1', 'yes' => '1', 'dir' => 'x']);

// psql-Kurzformen
$parses('Kurzformen mit Leerzeichen', ['check', '-h', 'db1', '-p', '5433', '-U', 'postgres', '-d', 'app'],
  ['command' => 'check', 'host' => 'db1', 'port' => '5433', 'user' => 'postgres', 'dbname' => 'app']);
$parses('Kurzformen zusammengeschrieben', ['check', '-hdb1', '-p5433', '-Upostgres', '-dapp'],
  ['host' => 'db1', 'port' => '5433', 'user' => 'postgres', 'dbname' => 'app']);
$parses('lange Namen mit Leerzeichen', ['check', '--host', 'db1', '--output', 'bericht', '--file', 'alt'],
  ['host' => 'db1', 'output' => 'bericht', 'file' => 'alt']);
$parses('-o und -f als Kurzformen', ['check', '-f', 'audit.261021', '-o', 'audit.%y%m%d'], ['file' => 'audit.261021', 'output' => 'audit.%y%m%d']);
$parses('-o zusammengeschrieben', ['client', '-obericht.html'], ['command' => 'client', 'output' => 'bericht.html']);
$parses('psql-Name --username', ['check', '--username', 'postgres'], ['user' => 'postgres']);
$parses('Optionen vor dem Befehl', ['-h', 'db1', 'check'], ['command' => 'check', 'host' => 'db1']);
$parses('Hilfe -?', ['-?'], ['help' => '1']);
$parses('client --user bleibt das Konto', ['client', '--user=alice'], ['command' => 'client', 'user' => 'alice']);
$parses('Wert mit = im Inhalt', ['check', '--rules=a.b,c.d'], ['rules' => 'a.b,c.d']);

// Abweisungen
$refuses('Kurzform mit = (würde Host „=db1“)', ['check', '-h=db1'], 'der Wert beginnt mit =');
$refuses('Langform mit == (würde Host „=db1“)', ['check', '--host==db1'], 'der Wert beginnt mit =');
$refuses('Wert als nächstes Argument mit =', ['check', '--host', '=db1'], 'der Wert beginnt mit =');
$refuses('-h ohne Wert verweist auf die Hilfe', ['check', '-h'], 'Hilfe ist --help oder -?');
$refuses('Wert darf keine Option sein', ['check', '-h', '-p', '5432'], 'braucht einen Wert');
$refuses('--host ohne Wert am Ende', ['check', '--host'], 'braucht einen Wert');
$refuses('leerer Wert', ['check', '--host='], 'braucht einen Wert');
$refuses('doppelt über Kurz- und Langform', ['check', '-h', 'a', '--host=b'], 'mehrfach');
$refuses('doppelt über --username und --user', ['check', '--username=a', '--user=b'], 'mehrfach');
$refuses('-U bei client', ['client', '-U', 'alice'], 'Datenbankbenutzer');
$refuses('--username bei client', ['client', '--username=alice'], 'Datenbankbenutzer');
$refuses('unbekannte Kurzform', ['check', '-x'], 'Unbekannte Option -x');
$refuses('psql -W (Passwortabfrage) gibt es nicht', ['check', '-W'], 'Unbekannte Option -W');
$refuses('Passwort als Option', ['check', '--password=geheim'], 'nicht auf die Kommandozeile');
$refuses('Schalter mit Wert', ['apply', '--execute=1'], 'Schalter');
$refuses('Kurzform-Schalter mit Wert', ['-?x'], 'Schalter');
$refuses('zweiter Befehl', ['check', 'plan'], 'Unbekanntes Argument');
$refuses('Wert vergessen, Befehl als Wert verschluckt', ['--host', 'check'], 'Kein Befehl angegeben');
$refuses('Optionen ohne Befehl', ['-o', 'bericht'], 'Kein Befehl angegeben');
$refuses('alte Option --format gibt es nicht mehr', ['check', '--format=json'], 'Unbekannte Option --format');
$refuses('alte Option --out gibt es nicht mehr', ['check', '--out=x.html'], 'Unbekannte Option --out');
$refuses('alte Option --previous gibt es nicht mehr', ['check', '--previous=x.json'], 'Unbekannte Option --previous');
$refuses('-o doppelt', ['check', '-o', 'a', '--output=b'], 'mehrfach');
$parses('ohne Argumente: Hilfe', [], ['command' => '']);
$parses('Hilfe gewinnt gegen kaputte Option', ['--help', '-o'], ['help' => '1']);
$parses('-? gewinnt gegen kaputte Option', ['check', '-h', '-?'], ['help' => '1']);
$parses('Schalter vor dem Befehl', ['--execute', 'apply', '--dir=x'], ['command' => 'apply', 'execute' => '1']);
// libpq nimmt einen Datenbanknamen mit "=" nicht als Verbindungsstring (gemessen: die ganze Zeichenkette ist der Name)
$parses('Datenbankname mit = und Leerzeichen bleibt ein Name', ['check', '-d', 'app port=1'], ['dbname' => 'app port=1']);

// Namen von -o und -f (ReportName): Endung wählt das Format, jeder andere Punkt gehört zum Namen; Platzhalter wie log_filename
$at = new DateTimeImmutable('2026-10-28 07:05:09');
$names = function (string $name, string $input, string|array $want, ?string $kind = 'outputs') use (&$failed, &$total, $at): void {
  $total++;
  try {
    $got = $kind === 'outputs' ? ReportName::outputs($input, $at) : ReportName::previous($input);
  } catch (HardenException $e) {
    $got = 'abgewiesen: ' . $e->getMessage();
  }
  $ok = is_array($want) ? $got === $want : is_string($got) && str_contains($got, $want);
  if (!$ok) {
    $failed++;
    echo "FEHLER $name: " . var_export($got, true) . ' (erwartet ' . var_export($want, true) . ")\n";
  }
};
$names('-o ohne Endung: JSON und HTML', 'bericht', ['bericht.json' => 'json', 'bericht.html' => 'html']);
$names('-o Punkt im Namen ist keine Endung', 'audit.261028', ['audit.261028.json' => 'json', 'audit.261028.html' => 'html']);
$names('-o .json allein', 'r.json', ['r.json' => 'json']);
$names('-o .html allein', 'r.html', ['r.html' => 'html']);
$names('-o .htm ist HTML', 'r.htm', ['r.htm' => 'html']);
$names('-o .txt ist Text', 'r.txt', ['r.txt' => 'text']);
$names('-o Endung ohne Rücksicht auf Groß/klein', 'R.JSON', ['R.JSON' => 'json']);
$names('-o Punkt im Verzeichnis', 'out.v2/bericht', ['out.v2/bericht.json' => 'json', 'out.v2/bericht.html' => 'html']);
$names('-o Platzhalter', 'audit.%y%m%d', ['audit.261028.json' => 'json', 'audit.261028.html' => 'html']);
$names('-o alle Platzhalter', '%Y-%m-%d_%H%M%S.txt', ['2026-10-28_070509.txt' => 'text']);
$names('-o %% ist ein Prozentzeichen', '100%%.json', ['100%.json' => 'json']);
$names('-o unbekannter Platzhalter', 'audit.%a', 'unbekannter Platzhalter %a');
$names('-o % am Ende', 'audit%', 'unbekannter Platzhalter %');
$names('-o Verzeichnis statt Name', 'berichte/', 'kein Verzeichnis');
$names('-o nur Endung', '.json', 'Namen vor der Endung');
$names('-o nur Punkt', '.', 'Namen vor der Endung');
$names('-o Punkte im Verzeichnis, Name leer', 'x/..html', 'Namen vor der Endung');
$names('-o versteckter Stamm mit Namen bleibt erlaubt', '.audit', ['.audit.json' => 'json', '.audit.html' => 'html']);
$names('-f ohne Endung liest .json', 'audit.261021', 'audit.261021.json', 'previous');
$names('-f mit .json', 'alt.json', 'alt.json', 'previous');
$names('-f mit .html abgewiesen', 'alt.html', 'JSON-Bericht', 'previous');
$names('-f mit .txt abgewiesen', 'alt.txt', 'JSON-Bericht', 'previous');

echo $failed === 0 ? "OK: $total Fälle\n" : "FEHLER: $failed von $total Fällen\n";
exit($failed === 0 ? 0 : 1);
