<?php
declare(strict_types=1);

/**
 * Offline test of the HTML report (HtmlRenderer): a report full of hostile values — markup, quotes, control, bidi and
 * zero-width characters, an unknown severity in the earlier report of a comparison (-f) — must come out escaped, as one file
 * without any external resource, with a CSP that admits exactly the one stylesheet. Runs without a PostgreSQL server:
 * php tests/html-report-test.php
 */

define('PG_HARDEN_LIBRARY', true);
require_once dirname(__DIR__) . '/pg-harden.php';

$failed = 0;
$total = 0;
$check = function (string $name, bool $ok) use (&$failed, &$total): void {
  $total++;
  if (!$ok) {
    $failed++;
    echo "FEHLER $name\n";
  }
};

$evil = "<script>alert(1)</script>\"'&</style><img src=x onerror=alert(2)>\e[31m\x00\u{202E}\u{200B}";
$result = fn(string $id, string $status, string $severity, bool $incomplete = false, array $findings = []) => [
  'id' => $id,
  'title' => "Titel $evil",
  'category' => "Bereich $evil",
  'severity' => $severity,
  'status' => $status,
  'incomplete' => $incomplete,
  'notes' => ["Hinweis $evil"],
  'findings' => $findings,
  'checked_databases' => ['shop'],
];
$finding = ['database' => "db $evil", 'object' => "obj $evil", 'detail' => "detail $evil"];
$results = [
  $result("hba.$evil", 'fail', 'high', true, [$finding, ['database' => null, 'object' => 'Zeile 1', 'detail' => '']]),
  $result('log.connections', 'fail', 'medium', false, [$finding]),
  $result('auth.auth_delay', 'fail', 'low', false, [$finding]),
  $result('x.info_fail', 'fail', 'info', false, [$finding]),
  $result('code.extensions', 'info', 'info'),
  $result('os.service_unit', 'pass', 'medium', true),
  $result('client.pgpass_acl', 'skip', 'low'),
  $result('os.umask', 'error', 'low'),
  $result('tls.ssl_enabled', 'pass', 'high'),
];
$counts = ['pass' => 2, 'fail' => 4, 'info' => 1, 'skip' => 1, 'error' => 1, 'incomplete' => 2];
$meta = [
  'tool' => 'pg-harden ' . PG_HARDEN_VERSION, 'mode' => 'server', 'created_at' => "2026-10-28T12:00:00+00:00",
  'host' => "h $evil", 'server' => "srv $evil", 'ssl' => false, 'certificate_verified' => false, 'remote' => true,
  'server_version' => "18 $evil", 'user' => "usr $evil", 'superuser' => true, 'local_server' => false, 'local_note' => "note $evil",
  'databases' => ["shop $evil", 'postgres'], 'refused_databases' => ["geheim $evil" => "kein CONNECT $evil"],
  'catalog' => "kat $evil", 'counts' => $counts, 'mapping_disclaimer' => MAPPING_DISCLAIMER, 'notice' => RESPONSIBILITY_NOTICE,
  'legal_notice' => LEGAL_NOTICE,
];
$mappings = [
  "k $evil" => ['framework' => "Rahmen $evil", 'verified' => false, 'note' => "Notiz $evil", 'controls' => [
    ['control' => "A1 $evil", 'title' => "Thema $evil", 'state' => 'Befund', 'rules_clean' => '0 von 1', 'rules' => ["hba.$evil"]],
    ['control' => 'A2', 'title' => 'Thema', 'state' => "unbekannt $evil", 'rules_clean' => '1 von 1', 'rules' => ['tls.ssl_enabled']],
  ]],
  'leer' => ['framework' => 'Ohne Treffer', 'verified' => true, 'note' => '', 'controls' => []],
];
$report = ['meta' => $meta, 'results' => $results, 'mappings' => $mappings];

// Vergleich (-f): the previous report is a file of unknown origin — unknown severities, hostile names; one finding fixed on a fully
// checked rule, one on a rule this run no longer has (not comparable).
$previous = $report;
$previous['meta']['created_at'] = "gestern $evil";
$previous['results'][1]['severity'] = ['kein', 'Text'];
$previous['results'][2]['severity'] = "evil\" class=\"x";
$previous['results'][] = $result("weg.$evil", 'fail', 'critical', false, [$finding]);
$previous['results'][1]['findings'][] = ['database' => null, 'object' => "fort $evil"];
$compared = $report;
$compared['comparison'] = Verifier::compare($previous, $report);
$client = ['meta' => ['mode' => 'client', 'counts' => array_fill_keys(array_keys($counts), 0)] + $meta, 'results' => [], 'mappings' => []];

// Protocols of apply and rollback: plan, journal and server values are just as untrusted.
$applyLog = [
  'started_at' => '2026-10-28T12:00:00+00:00', 'finished_at' => '2026-10-28T12:00:09+00:00', 'server' => "srv $evil", 'server_version' => "18 $evil",
  'user' => "usr $evil", 'dir' => "/root/j $evil", 'outcome' => 'failed',
  'plan' => [
    'conf' => [['rule' => "log.$evil", 'name' => "name $evil", 'value' => "wert $evil", 'restart' => true]],
    'hba' => [['rule' => 'hba.trust', 'line' => 117, 'kind' => 'method', 'from' => ["trust $evil"], 'to' => "scram $evil"]],
    'sql' => ["db $evil" => [
      ['rule' => 'db.public_schema_create', 'object' => 'o', 'fix_sql' => "REVOKE $evil;"],
      ['rule' => 'code.secdef_search_path', 'object' => 'o', 'fix_sql' => "ALTER $evil;"],
    ]],
    'notes' => ["Hinweis $evil"],
  ],
  'skipped_confirm' => ["hba.$evil"], 'skipped_other' => [["x.$evil", "Grund $evil"]],
  'steps' => [
    ['at' => '2026-10-28T12:00:01+00:00', 'phase' => "Phase $evil", 'status' => 'OK', 'message' => "ok $evil"],
    ['at' => "zeit $evil", 'phase' => 'SQL', 'status' => "unbekannt $evil", 'message' => "fehler $evil"],
  ],
  'files' => [['path' => "/etc/$evil", 'action' => 'modified', 'backup' => "backup/01-$evil"], ['path' => '/x', 'action' => 'created', 'backup' => null]],
  'sql' => [['database' => "db $evil", 'rule' => 'db.public_schema_create', 'fix_sql' => "REVOKE $evil;", 'rollback_sql' => null, 'status' => 'committed']],
  'before_counts' => $counts, 'after' => $compared, 'post_error' => null,
];
$aborted = ['outcome' => 'aborted', 'finished_at' => null, 'after' => null, 'post_error' => "kaputt $evil", 'steps' => [], 'files' => [], 'sql' => []] + $applyLog;
$aborted['plan'] = ['conf' => [], 'hba' => [], 'sql' => [], 'notes' => []];
$rollbackLog = [
  'started_at' => '2026-10-28T13:00:00+00:00', 'finished_at' => '2026-10-28T13:00:02+00:00', 'server' => "srv $evil", 'server_version' => '18',
  'user' => 'postgres', 'dir' => "/root/j $evil", 'apply_started_at' => "apply $evil", 'ok' => false, 'log_file' => 'rollback-attempt-1.json',
  'steps' => [['status' => 'FEHLER', 'message' => "nicht $evil"], ['status' => 'WARNUNG', 'message' => 'w']],
];

$cases = ['check' => $report, 'check -f' => $compared, 'client' => $client];
$pages = [];
foreach ($cases as $name => $r) {
  try {
    $pages[$name] = HtmlRenderer::render($r);
    $check("$name: Textbericht entsteht", TextRenderer::render($r) !== '');
  } catch (Throwable $e) {
    $check("$name: rendert ohne Fehler ({$e->getMessage()})", false);
  }
}
foreach (['apply' => fn() => HtmlRenderer::applyLog($applyLog), 'apply-abgebrochen' => fn() => HtmlRenderer::applyLog($aborted),
  'rollback' => fn() => HtmlRenderer::rollbackLog($rollbackLog), 'rollback-ok' => fn() => HtmlRenderer::rollbackLog(['ok' => true] + $rollbackLog)] as $name => $make) {
  try {
    $pages[$name] = $make();
  } catch (Throwable $e) {
    $check("$name: rendert ohne Fehler ({$e->getMessage()})", false);
  }
}
foreach ($pages as $name => $html) {

  // One stylesheet, admitted by its hash; nothing else may load or run.
  $check("$name: genau ein style-Element", substr_count($html, '<style>') === 1 && substr_count($html, '</style>') === 1);
  preg_match('~<style>(.*)</style>~s', $html, $style);
  preg_match('~<meta http-equiv="Content-Security-Policy" content="([^"]*)">~', $html, $csp);
  $check("$name: CSP vorhanden", isset($csp[1]));
  $check("$name: CSP default-src 'none' und Hash des Stylesheets",
    isset($csp[1], $style[1]) && $csp[1] === "default-src 'none'; style-src 'sha256-" . base64_encode(hash('sha256', $style[1], true))
      . "'; base-uri 'none'; form-action 'none'");
  // Every tag outside the stylesheet: known element, known attribute, nothing else (escaped text holds no "<").
  $markup = str_replace($style[0] ?? '', '', $html);
  $elements = ['!doctype', 'html', 'head', 'meta', 'title', 'body', 'header', 'nav', 'main', 'section', 'footer', 'h1', 'h2', 'h3', 'p', 'span',
    'div', 'dl', 'dt', 'dd', 'ol', 'ul', 'li', 'a', 'code', 'strong', 'svg', 'rect', 'table', 'thead', 'tbody', 'tr', 'th', 'td'];
  $attributes = ['lang', 'charset', 'name', 'content', 'http-equiv', 'class', 'id', 'href', 'aria-label', 'aria-hidden', 'role', 'scope',
    'data-label', 'width', 'height', 'x', 'y', 'html'];
  preg_match_all('~<(/?)([^\s>/]+)([^>]*)>~', $markup, $tags, PREG_SET_ORDER);
  $badTags = [];
  foreach ($tags as [$tag, , $element, $rest]) {
    preg_match_all('~\s([^\s=]+)(?:="[^"]*")?~', $rest, $attr);
    if (!in_array(strtolower($element), $elements, true) || array_diff($attr[1], $attributes, ['/']) !== []) {
      $badTags[] = $tag;
    }
  }
  $check("$name: nur bekannte Elemente und Attribute (" . implode(' ', array_slice($badTags, 0, 3)) . ')', $badTags === []);
  $check("$name: kein < im Text", substr_count($markup, '<') === count($tags));
  $check("$name: Stylesheet ohne externe Bezüge", !preg_match('~url\(|@import|https?:|<~i', $style[1] ?? ''));
  preg_match_all('~href="([^"]*)"~', $html, $hrefs);
  $check("$name: nur Sprungmarken innerhalb der Datei", array_filter($hrefs[1], fn($h) => preg_match('~^#[a-z0-9-]+$~', $h) !== 1) === []);

  // Every value escaped: no raw markup, no control or format character survives.
  $check("$name: Werte maskiert", !str_contains($html, '<script>alert') && str_contains($html, '&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#039;&amp;'));
  $check("$name: Steuer- und Formatzeichen sichtbar gemacht", preg_match('~[\x00-\x08\x0B-\x1F\x7F]|\x{202E}|\x{200B}~u', $html) !== 1
    && str_contains($html, '\u{1B}[31m\u{0}\u{202E}\u{200B}'));

  // Class names and ids come from fixed keys only.
  preg_match_all('~class="([^"]*)"~', $html, $classes);
  $known = ['k-high', 'k-medium', 'k-low', 'k-info', 'k-review', 'k-error', 'k-incomplete', 'k-skip', 'k-pass'];
  $bad = array_filter($classes[1], fn($c) => preg_match('~^[a-z0-9 -]+$~', $c) !== 1
    || array_diff(preg_grep('~^k-~', explode(' ', $c)), $known) !== []);
  $check("$name: Klassen nur aus festen Schlüsseln", $bad === []);
  preg_match_all('~ id="([^"]*)"~', $html, $ids);
  $check("$name: ids eindeutig und fest", count($ids[1]) === count(array_unique($ids[1])) && preg_grep('~^[a-z0-9-]+$~', $ids[1], PREG_GREP_INVERT) === []);
  $check("$name: jede Sprungmarke hat ihr Ziel", array_diff(array_map(fn($h) => substr($h, 1), $hrefs[1]), $ids[1]) === []);
}

$html = $pages['apply'] ?? '';
$check('apply: Ergebnis fehlgeschlagen', str_contains($html, '<p class="banner k-high"><strong>Fehlgeschlagen</strong>'));
$check('apply: SQL-Stand aus dem Journal', str_contains($html, '<span class="badge k-pass">ausgeführt</span></td><td data-label="Anweisung"><code>REVOKE &lt;script&gt;')
  && str_contains($html, '<span class="badge k-skip">nicht ausgeführt</span></td><td data-label="Anweisung"><code>ALTER &lt;script&gt;'));
$check('apply: unbekannter Schrittstatus grau, Zeit unverändert', str_contains($html, '<span class="badge k-skip">unbekannt &lt;script&gt;')
  && str_contains($html, '<td class="num">zeit &lt;script&gt;') && str_contains($html, '<td class="num">12:00:01</td>'));
$check('apply: Neustart, Freigabe, Dateien, Vergleich, Journal', str_contains($html, 'Neustart nötig') && str_contains($html, 'id="skipped"')
  && str_contains($html, 'id="files"') && str_contains($html, 'id="comparison"') && str_contains($html, 'rollback --dir=/root/j &lt;script&gt;'));
$html = $pages['apply-abgebrochen'] ?? '';
$check('apply abgebrochen: nicht beendet, Nachprüfung mit Meldung, keine leeren Abschnitte', str_contains($html, '<strong>Abgebrochen</strong>')
  && str_contains($html, 'nicht beendet') && str_contains($html, '<strong>Nicht möglich:</strong> kaputt &lt;script&gt;')
  && str_contains($html, 'Keine Schritte protokolliert') && !str_contains($html, 'id="files"') && str_contains($html, '<p class="note">keine</p>'));
$okLog = HtmlRenderer::applyLog(['outcome' => 'ok'] + $applyLog);
$check('apply ohne Fehler: offene Befunde im Ergebnissatz', str_contains($okLog, '<strong>Ausgeführt</strong> — Alle Schritte ohne Fehler; die Nachprüfung ist gelaufen. 4 Befunde bleiben offen (Vergleich unten).'));
$check('rollback: unvollständig mit Wiederholungshinweis', str_contains($pages['rollback'] ?? '', '<strong>Rückweg unvollständig</strong>')
  && str_contains($pages['rollback'] ?? '', 'rollback-attempt-1.json'));
$check('rollback: abgeschlossen', str_contains($pages['rollback-ok'] ?? '', '<p class="banner k-pass"><strong>Rückweg abgeschlossen</strong>'));
$check('Protokolle nennen sich Protokoll', str_contains($pages['rollback'] ?? '', 'Das Protokoll enthält Rollen-'));
$deletion = 'Rollennamen können personenbeziehbar sein; nach Abschluss zeitnah löschen.';
$check('Protokolle tragen den Löschhinweis (ohne Rechtstext)', str_contains($pages['rollback'] ?? '', $deletion) && str_contains($okLog, $deletion));
$check('Bericht ohne Löschhinweis im Kopf (steht im Rechtstext)', !str_contains(HtmlRenderer::render($compared), $deletion));
$noLegal = $compared;
$noLegal['meta']['legal_notice'] = null;
$check('Bericht ohne Rechtstext bekommt den Protokoll-Hinweis trotzdem nicht', !str_contains(HtmlRenderer::render($noLegal), $deletion)
  && !str_contains(HtmlRenderer::render($noLegal), 'Bestimmungsgemäße Verwendung'));

$html = HtmlRenderer::render($compared);
$check('Vergleich: Vergleichsabschnitt', str_contains($html, 'id="comparison"') && str_contains($html, 'Behoben 1') && str_contains($html, 'Neu 0'));
$check('Vergleich: unbekannte Schwere des Vorberichts bleibt leer', $compared['comparison']['fixed'][0]['severity'] === null);
$check('Zuordnung ohne Treffer fehlt', !str_contains($html, 'Ohne Treffer'));
$check('unbekannter Zuordnungsstand grau', str_contains($html, '<span class="badge k-skip">unbekannt &lt;script&gt;'));
$check('Befund unvollständig gekennzeichnet', str_contains($html, '<span class="badge k-incomplete">nicht vollständig geprüft</span>'));
$check('Achtung bei ungeprüftem Zertifikat', str_contains($html, '<dd class="warn">Serverzertifikat nicht geprüft'));
$check('Hinweis zur Verwendung am Ende', str_contains($html, 'Bestimmungsgemäße Verwendung:'));
$check('Abschnitte in der Reihenfolge des Textberichts', preg_match('~id="summary".*id="comparison".*id="findings-high".*id="findings-medium"'
  . '.*id="findings-low".*id="findings-info".*id="rules-error".*id="rules-info".*id="rules-incomplete".*id="rules-skip".*id="rules-pass"'
  . '.*id="mapping-1".*id="notices"~s', $html) === 1);

// The previous report is checked before any comparison: types that would break the renderers are refused there.
$asPrevious = $previous;
$asPrevious['meta']['tool'] = 'pg-harden 0.4.0';
$check('Vorbericht mit gültigen Typen angenommen', Verifier::isReport($asPrevious));
$broken = $asPrevious;
$broken['results'][0]['findings'][0]['object'] = 17;
$check('Vorbericht: Fundstelle als Zahl abgewiesen', !Verifier::isReport($broken));
$broken = $asPrevious;
$broken['results'][0]['id'] = ['a'];
$check('Vorbericht: Regelkennung als Array abgewiesen', !Verifier::isReport($broken));
$broken = $asPrevious;
$broken['meta']['mode'] = ['client'];
$check('Vorbericht: Modus als Array abgewiesen', !Verifier::isReport($broken));

// Dates are read only in the form pg-harden writes; anything else stays visible as it is.
$check('Datum ATOM', TextRenderer::when('2026-10-28T12:00:00+00:00') === '28.10.2026 12:00 (+00:00)');
$check('Datum mit Sekundenbruchteilen', TextRenderer::when('2026-10-28T12:00:00.123456+02:00') === '28.10.2026 12:00 (+02:00)');
$check('kein Datum aus „now“', TextRenderer::when('now') === 'now');
$check('kein Datum über NUL hinweg', TextRenderer::when("2026-01-01\x00x") === '2026-01-01\u{0}x');
$check('kein übergelaufenes Datum', TextRenderer::when('2026-02-31T12:00:00+00:00') === '2026-02-31T12:00:00+00:00');
$check('leeres Datum', TextRenderer::when('') === '');
foreach (['2026-10-28T12:00:00+99:99', '26-10-28T12:00:00+00:00', '2026-10-28T12:00:00Z', '2026-10-28T12:00:00 Europe/Berlin',
  '2026-10-28T12:00:00+01:30:45', ' 2026-10-28T12:00:00+00:00', '2026-10-28T12:00:60+00:00'] as $raw) {
  $check("kein Datum aus »{$raw}«", TextRenderer::when($raw) === $raw);
}

$empty = HtmlRenderer::render($client);
$check('Client ohne Ergebnisse: keine Leiste, 0 Befunde', !str_contains($empty, '<svg') && str_contains($empty, '<span class="n">0</span> <span class="l">Befunde</span>'));

echo $failed === 0 ? "OK: $total Fälle\n" : "FEHLER: $failed von $total Fällen\n";
exit($failed === 0 ? 0 : 1);
