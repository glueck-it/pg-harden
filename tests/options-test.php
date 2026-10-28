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
$parses('lange Namen mit Leerzeichen', ['check', '--host', 'db1', '--out', 'bericht.html', '--format', 'html'],
  ['host' => 'db1', 'out' => 'bericht.html', 'format' => 'html']);
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
$refuses('Optionen ohne Befehl', ['--format=json'], 'Kein Befehl angegeben');
$parses('ohne Argumente: Hilfe', [], ['command' => '']);
$parses('Hilfe gewinnt gegen kaputte Option', ['--help', '--format'], ['help' => '1']);
$parses('-? gewinnt gegen kaputte Option', ['check', '-h', '-?'], ['help' => '1']);
$parses('Schalter vor dem Befehl', ['--execute', 'apply', '--dir=x'], ['command' => 'apply', 'execute' => '1']);
// libpq nimmt einen Datenbanknamen mit "=" nicht als Verbindungsstring (gemessen: die ganze Zeichenkette ist der Name)
$parses('Datenbankname mit = und Leerzeichen bleibt ein Name', ['check', '-d', 'app port=1'], ['dbname' => 'app port=1']);

echo $failed === 0 ? "OK: $total Fälle\n" : "FEHLER: $failed von $total Fällen\n";
exit($failed === 0 ? 0 : 1);
