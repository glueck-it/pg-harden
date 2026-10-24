<?php
declare(strict_types=1);

// Builds the version × rule table (Markdown) from the check reports written by run-version-matrix.sh.
// Usage: php tests/matrix-table.php <out-dir>   (reads <out-dir>/<tag>.check.json)
// A rule that passed but could not be checked completely is shown as "nicht geprüft", never as "pass".

$dir = $argv[1] ?? null;
if ($dir === null || !is_dir($dir)) {
  fwrite(STDERR, "usage: php tests/matrix-table.php <out-dir>\n");
  exit(2);
}
$files = [];
foreach (scandir($dir) ?: [] as $name) {
  if (preg_match('/^(.+)\.check\.json$/', $name, $m) === 1) {
    $files[$m[1]] = rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . $name;
  }
}
uksort($files, 'strnatcmp');
$status = [];
$notes = [];
$tags = [];
foreach ($files as $tag => $f) {
  $j = json_decode((string) file_get_contents($f), true);
  if (!is_array($j) || !is_array($j['results'] ?? null)) {
    fwrite(STDERR, "$tag: kein lesbarer Bericht\n");
    continue;
  }
  $tags[] = $tag;
  foreach ($j['results'] as $r) {
    if (!isset($r['id'], $r['status'])) {
      continue;
    }
    $s = (string) $r['status'];
    $incomplete = !empty($r['incomplete']);
    $label = $s === 'error' ? 'FEHLER' : ($s === 'pass' && $incomplete ? 'nicht geprüft' : $s);
    $status[$r['id']][$tag] = $label;
    if ($s === 'error' || $incomplete) {
      $notes[$r['id']][$tag] = implode(' / ', array_map('strval', is_array($r['notes'] ?? null) ? $r['notes'] : []));
    }
  }
}
if ($tags === []) {
  fwrite(STDERR, "keine Berichte (*.check.json) in $dir\n");
  exit(2);
}
echo '| Regel | ' . implode(' | ', $tags) . " |\n|---|" . str_repeat('---|', count($tags)) . "\n";
ksort($status);
foreach ($status as $id => $row) {
  echo "| `$id` | " . implode(' | ', array_map(fn($t) => $row[$t] ?? '–', $tags)) . " |\n";
}
echo "\nStatuswerte je Version:\n\n";
foreach ($tags as $t) {
  $c = array_count_values(array_column($status, $t));
  ksort($c);
  echo "- $t: " . implode(', ', array_map(fn($k, $v) => "$k $v", array_keys($c), $c)) . "\n";
}
if ($notes !== []) {
  echo "\nHinweise zu Fehlern und unvollständigen Prüfungen:\n\n";
  foreach ($notes as $id => $byTag) {
    foreach ($byTag as $t => $n) {
      echo "- `$id` ($t): " . substr($n, 0, 200) . "\n";
    }
  }
}
