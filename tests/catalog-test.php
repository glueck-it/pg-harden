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
$expect('Programmversion ist 0.4.0', PG_HARDEN_VERSION === '0.4.0', PG_HARDEN_VERSION);
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
