<?php
declare(strict_types=1);

/**
 * Offline regression test for the rule catalog, framework mappings, Verifier (server + client) and ClientProbes::psqlHistory.
 * Runs without a PostgreSQL server or root/admin privileges: php tests/catalog-test.php
 */

define('PG_HARDEN_LIBRARY', true);
require_once dirname(__DIR__) . '/pg-harden.php';

$failed = 0;
$total = 0;
$expect = function (string $name, bool $ok, string $detail = '') use (&$failed, &$total): void {
  $total++;
  if (!$ok) {
    $failed++;
    echo "FEHLER $name" . ($detail !== '' ? ": $detail" : '') . "\n";
  }
};

$catalog = Catalog::load(dirname(__DIR__));
$expect('Programmversion ist 0.4.1', PG_HARDEN_VERSION === '0.4.1', PG_HARDEN_VERSION);
$expect('Katalogversion gesetzt', str_contains($catalog->version, '2026.10'), $catalog->version);
$expect('86 Regeln im Katalog', count($catalog->rules) === 86, (string) count($catalog->rules));
$expect('3 Norm-Zuordnungen geladen', count($catalog->mappings) === 3, (string) count($catalog->mappings));

$byFile = ['check' => 0, 'client' => 0];
$overlongIds = [];
foreach ($catalog->rules as $id => $rule) {
  $byFile[$rule->command()] = ($byFile[$rule->command()] ?? 0) + 1;
  if (strlen($id) > 28) {
    $overlongIds[] = $id;
  }
}
$expect('Alle Regelkennungen höchstens 28 Zeichen (TextRenderer-Spaltenbreite)', $overlongIds === [], implode(', ', $overlongIds));
$expect('74 Server-Regeln (check)', $byFile['check'] === 74, (string) $byFile['check']);
$expect('12 Client-Regeln (client)', $byFile['client'] === 12, (string) $byFile['client']);

foreach ($catalog->mappings as $map) {
  $covered = [];
  foreach ($map['controls'] ?? [] as $ctl => $def) {
    foreach ($def['rules'] ?? [] as $id) {
      $covered[$id] = true;
    }
  }
  $missing = array_diff(array_keys($catalog->rules), array_keys($covered));
  $expect('Alle 86 Regeln in ' . ($map['short'] ?? $map['framework']) . ' zugeordnet', $missing === [], implode(', ', $missing));
}

$sampleReport = [
  'meta' => [
    'tool' => 'pg-harden 0.4.0',
    'catalog' => '0.4.0',
    'created_at' => '2026-10-28T12:00:00+00:00',
    'mode' => 'server',
    'server' => 'db1:5432',
    'server_version' => '17.2',
    'user' => 'postgres',
    'databases' => ['postgres', 'shop'],
  ],
  'results' => [
    [
      'id' => 'hba.trust',
      'title' => 'Verbindungen mit trust',
      'severity' => 'critical',
      'status' => 'fail',
      'incomplete' => false,
      'checked_databases' => [],
      'findings' => [['database' => null, 'object' => 'Zeile 90', 'detail' => 'trust']],
    ],
    [
      'id' => 'db.public_schema_create',
      'title' => 'CREATE im Schema public',
      'severity' => 'high',
      'status' => 'fail',
      'incomplete' => false,
      'checked_databases' => ['postgres', 'shop'],
      'findings' => [['database' => 'shop', 'object' => 'schema public', 'detail' => 'PUBLIC hat CREATE']],
    ],
  ],
];

$expect('Verifier::isReport akzeptiert 0.4.0', Verifier::isReport($sampleReport));
$r02 = $sampleReport;
$r02['meta']['tool'] = 'pg-harden 0.2.0';
$expect('Verifier::isReport akzeptiert 0.2.0', Verifier::isReport($r02));
$r10 = $sampleReport;
$r10['meta']['tool'] = 'pg-harden 1.0.0';
$expect('Verifier::isReport akzeptiert 1.0.0', Verifier::isReport($r10));
$r01 = $sampleReport;
$r01['meta']['tool'] = 'pg-harden 0.1.0';
$expect('Verifier::isReport weist 0.1.0 ab', !Verifier::isReport($r01));

$afterServer = $sampleReport;
$afterServer['results'][0]['status'] = 'pass';
$afterServer['results'][0]['findings'] = [];
$afterServer['results'][1]['checked_databases'] = ['postgres'];
$afterServer['results'][1]['incomplete'] = true;
$afterServer['results'][1]['status'] = 'pass';
$afterServer['results'][1]['findings'] = [];
$diffServer = Verifier::compare($sampleReport, $afterServer);
$expect('Verifier::compare Server: hba.trust als behoben erkannt', count($diffServer['fixed']) === 1 && $diffServer['fixed'][0]['rule'] === 'hba.trust');
$expect('Verifier::compare Server: nicht erneut geprüfte DB als not_comparable erkannt', count($diffServer['not_comparable']) === 1 && $diffServer['not_comparable'][0]['rule'] === 'db.public_schema_create');

$clientPrev = [
  'meta' => [
    'tool' => 'pg-harden 0.4.0',
    'catalog' => '0.4.0',
    'created_at' => '2026-10-28T12:00:00+00:00',
    'mode' => 'client',
    'server' => 'workstation1',
    'user' => 'alice',
  ],
  'results' => [
    [
      'id' => 'client.psql_history',
      'title' => 'psql-Verlaufsdatei',
      'severity' => 'high',
      'status' => 'fail',
      'incomplete' => false,
      'checked_databases' => [],
      'findings' => [['database' => null, 'object' => '/home/alice/.psql_history:2', 'detail' => 'ALTER ROLE mit Passwort']],
    ],
  ],
];
$clientCurr = $clientPrev;
$clientCurr['meta']['user'] = 'bob';
$clientCurr['results'][0]['status'] = 'pass';
$clientCurr['results'][0]['findings'] = [];
$diffClient = Verifier::compare($clientPrev, $clientCurr);
$expect('Verifier::compare Client: behobener Befund erkannt', count($diffClient['fixed']) === 1 && $diffClient['fixed'][0]['rule'] === 'client.psql_history');
$expect('Verifier::compare Client: abweichendes Konto gewarnt', $diffClient['warnings'] === ['Konto weicht ab: alice → bob'], implode('; ', $diffClient['warnings']));

// hba findings: an inserted line shifts the numbers, the selector (hba_key) stays.
$hbaRule = fn(array $findings) => [
  'id' => 'hba.host_without_tls', 'title' => 'TLS', 'severity' => 'medium', 'status' => $findings === [] ? 'pass' : 'fail',
  'incomplete' => false, 'checked_databases' => [], 'findings' => $findings,
];
// The selector as the rules build it: file:type ["databases"] ["users"] address/netmask
$hbaKey = function (string $line): string {
  [$type, $db, $user, $addr] = explode(' ', $line);
  return '/etc/pg_hba.conf:' . $type . ' ' . json_encode(explode(',', $db)) . ' ' . json_encode(explode(',', $user)) . ' ' . $addr;
};
$hbaF = fn(int $line, string $key, ?string $method = 'scram-sha-256') => ['database' => null, 'object' => "Zeile $line", 'detail' => "$key $method", 'hba_key' => $hbaKey($key)];
$hbaPrev = ['meta' => $sampleReport['meta'], 'results' => [$hbaRule([$hbaF(90, 'host all app 10.0.0.0/255.0.0.0'), $hbaF(91, 'host all all 192.168.0.0/255.255.0.0')])]];
$hbaCurr = ['meta' => $sampleReport['meta'], 'results' => [$hbaRule([$hbaF(91, 'host all app 10.0.0.0/255.0.0.0'), $hbaF(92, 'host all all 192.168.0.0/255.255.0.0')])]];
$d = Verifier::compare($hbaPrev, $hbaCurr);
$expect('Verifier::compare hba: eingefügte Zeile → beide weiter offen, nichts behoben/neu',
  count($d['open']) === 2 && $d['fixed'] === [] && $d['new'] === [] && $d['open'][0]['object'] === 'Zeile 91',
  json_encode([count($d['open']), count($d['fixed']), count($d['new'])]));
$hbaCurr2 = ['meta' => $sampleReport['meta'], 'results' => [$hbaRule([$hbaF(91, 'host all all 192.168.0.0/255.255.0.0', 'md5')])]];
$d = Verifier::compare($hbaPrev, $hbaCurr2);
$expect('Verifier::compare hba: entfernte Zeile behoben, Methodenwechsel bleibt offen',
  count($d['fixed']) === 1 && $d['fixed'][0]['object'] === 'Zeile 90' && count($d['open']) === 1 && $d['new'] === []);
$dup = ['meta' => $sampleReport['meta'], 'results' => [$hbaRule([$hbaF(5, 'host all all 10.0.0.0/255.0.0.0'), $hbaF(9, 'host all all 10.0.0.0/255.0.0.0')])]];
$dupCurr = ['meta' => $sampleReport['meta'], 'results' => [$hbaRule([$hbaF(6, 'host all all 10.0.0.0/255.0.0.0')])]];
$d = Verifier::compare($dup, $dupCurr);
$expect('Verifier::compare hba: zwei gleiche Zeilen, eine entfernt → 1 offen, 1 behoben', count($d['open']) === 1 && count($d['fixed']) === 1);
$old = $hbaPrev;
foreach ($old['results'][0]['findings'] as &$of) {
  unset($of['hba_key']);
}
unset($of);
$d = Verifier::compare($old, $hbaCurr);
$expect('Verifier::compare hba: Bericht ohne hba_key (vor 0.4.1) → Zuordnung über die Zeilennummer',
  count($d['open']) === 1 && $d['open'][0]['object'] === 'Zeile 91' && count($d['fixed']) === 1 && count($d['new']) === 1);
$md5 = fn(array $lines) => ['meta' => $sampleReport['meta'], 'results' => [array_merge($hbaRule(array_map(fn($l) => $hbaF($l, 'host all app 10.0.0.0/255.0.0.0', 'md5'), $lines)), ['id' => 'hba.md5_method'])]];
$d = Verifier::compare($md5([5, 9]), $md5([9]));
$expect('Verifier::compare hba: zwei gleiche Zeilen, die erste umgestellt → Zeile 5 behoben, Zeile 9 offen',
  count($d['fixed']) === 1 && $d['fixed'][0]['object'] === 'Zeile 5' && count($d['open']) === 1 && $d['open'][0]['object'] === 'Zeile 9',
  json_encode([$d['fixed'], $d['open']]));
$d = Verifier::compare($md5([5, 9]), $md5([6, 10]));
$expect('Verifier::compare hba: zwei gleiche Zeilen verschoben → beide offen', count($d['open']) === 2 && $d['fixed'] === [] && $d['new'] === []);
$d = Verifier::compare($md5([5]), $md5([2, 6]));
$expect('Verifier::compare hba: gleiche Zeile darüber hinzugekommen → eine neu, eine offen', count($d['open']) === 1 && count($d['new']) === 1 && $d['fixed'] === []);
$narrow = ['meta' => $sampleReport['meta'], 'results' => [$hbaRule([$hbaF(90, 'host all app 10.0.0.0/255.255.0.0'), $hbaF(91, 'host all all 192.168.0.0/255.255.0.0')])]];
$d = Verifier::compare($hbaPrev, $narrow);
$expect('Verifier::compare hba: Zeile an Ort und Stelle enger gefasst, Befund bleibt → offen, nicht behoben + neu',
  count($d['open']) === 2 && $d['fixed'] === [] && $d['new'] === [], json_encode([count($d['open']), count($d['fixed']), count($d['new'])]));
$replaced = ['meta' => $sampleReport['meta'], 'results' => [$hbaRule([$hbaF(90, 'host all ops 10.0.0.0/255.0.0.0'), $hbaF(91, 'host all all 192.168.0.0/255.255.0.0')])]];
$d = Verifier::compare($hbaPrev, $replaced);
$expect('Verifier::compare hba: Zeile an gleicher Stelle für andere Benutzer ersetzt → behoben + neu',
  count($d['fixed']) === 1 && count($d['new']) === 1 && count($d['open']) === 1, json_encode([count($d['open']), count($d['fixed']), count($d['new'])]));
$moved = ['meta' => $sampleReport['meta'], 'results' => [$hbaRule([$hbaF(91, 'host all all 192.168.0.0/255.255.0.0'), $hbaF(95, 'host all ops 172.16.0.0/255.240.0.0')])]];
$d = Verifier::compare($hbaPrev, $moved);
$expect('Verifier::compare hba: Zeile entfernt, andere neu an anderer Stelle → behoben + neu',
  count($d['fixed']) === 1 && $d['fixed'][0]['object'] === 'Zeile 90' && count($d['new']) === 1 && $d['new'][0]['object'] === 'Zeile 95' && count($d['open']) === 1);
$mixed = $hbaPrev;
unset($mixed['results'][0]['findings'][1]['hba_key']);
$d = Verifier::compare($mixed, $hbaCurr);
$expect('Verifier::compare hba: nur teilweise mit hba_key → Zeilennummer für die ganze Regel',
  count($d['open']) === 1 && $d['open'][0]['object'] === 'Zeile 91' && count($d['fixed']) === 1 && count($d['new']) === 1);
$bad = $hbaPrev;
$bad['results'][0]['findings'][0]['hba_key'] = ['x'];
$bad['results'][0]['findings'][1]['hba_key'] = 7;
$d = Verifier::compare($bad, $hbaCurr);
$expect('Verifier::compare hba: hba_key als Array/Zahl → Zeilennummer, keine Ausnahme', count($d['fixed']) === 1 && count($d['new']) === 1);
$err = fn(array $lines) => ['meta' => $sampleReport['meta'], 'results' => [array_merge($hbaRule(array_map(fn($l) => ['database' => null, 'object' => "Zeile $l", 'detail' => 'invalid IP mask', 'hba_key' => 'invalid IP mask'], $lines)), ['id' => 'hba.errors'])]];
$d = Verifier::compare($err([7]), $err([8]));
$expect('Verifier::compare hba.errors: verschobene fehlerhafte Zeile bleibt offen', count($d['open']) === 1 && $d['fixed'] === [] && $d['new'] === []);
$errText = fn(string $text) => ['meta' => $sampleReport['meta'], 'results' => [array_merge($hbaRule([['database' => null, 'object' => 'Zeile 7', 'detail' => $text, 'hba_key' => "/etc/pg_hba.conf:$text"]]), ['id' => 'hba.errors'])]];
$d = Verifier::compare($errText('invalid IP address "hostx"'), $errText('invalid IP address "hosty"'));
$expect('Verifier::compare hba.errors: anderer Fehler in derselben Zeile → behoben + neu', count($d['fixed']) === 1 && count($d['new']) === 1 && $d['open'] === []);

$tmp = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'pgh-cat-' . bin2hex(random_bytes(4));
mkdir($tmp, 0700, true);
try {
  $appData = $tmp . DIRECTORY_SEPARATOR . 'AppData';
  mkdir($appData . DIRECTORY_SEPARATOR . 'postgresql', 0700, true);
  $hist = Platform::windows() ? $appData . '\\postgresql\\psql_history' : $tmp . '/.psql_history';
  file_put_contents($hist, "SELECT 1;\nALTER ROLE app WITH PASSWORD 'TopSecretValue99';\n\\password postgres\n");
  @chmod($hist, 0644);
  $ctx = new ClientContext(
    account: 'tester',
    home: $tmp,
    appData: $appData,
    isSelf: true,
    sid: null,
    extraScanDirs: [],
  );
  $res = ClientProbes::run('psql_history', $ctx);
  $expect('ClientProbes::psqlHistory meldet Passwort im Verlauf', $res['findings'] !== [], json_encode($res));
  $dump = json_encode($res);
  $expect('ClientProbes::psqlHistory gibt niemals das Passwort selbst aus', !str_contains((string) $dump, 'TopSecretValue99'));
} finally {
  @unlink($tmp . DIRECTORY_SEPARATOR . 'AppData' . DIRECTORY_SEPARATOR . 'postgresql' . DIRECTORY_SEPARATOR . 'psql_history');
  @unlink($tmp . DIRECTORY_SEPARATOR . '.psql_history');
  @rmdir($tmp . DIRECTORY_SEPARATOR . 'AppData' . DIRECTORY_SEPARATOR . 'postgresql');
  @rmdir($tmp . DIRECTORY_SEPARATOR . 'AppData');
  @rmdir($tmp);
}

if ($failed > 0) {
  echo "$failed von $total Prüfungen fehlgeschlagen.\n";
  exit(1);
}
echo "OK: $total Fälle\n";
