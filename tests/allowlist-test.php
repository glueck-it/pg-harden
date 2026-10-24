<?php
declare(strict_types=1);

// Unit test for ServerFiles::sqlAllowed / pairAllowed (the allowlist apply and rollback run SQL through).
// Usage: php tests/allowlist-test.php   — prints one line per failed case, exit 1 on any failure.

define('PG_HARDEN_LIBRARY', true);
require __DIR__ . '/../pg-harden.php';

$cat = 'pg_catalog.pg_database, pg_catalog.pg_roles';
$allowedPairs = [
  ["REVOKE CREATE ON SCHEMA public FROM PUBLIC;", "GRANT CREATE ON SCHEMA public TO PUBLIC;"],
  ["REVOKE CONNECT ON DATABASE \"my db\" FROM PUBLIC;", "GRANT CONNECT ON DATABASE \"my db\" TO PUBLIC;"],
  ["REVOKE SELECT ON TABLE $cat FROM PUBLIC;", "GRANT SELECT ON TABLE $cat TO PUBLIC;"],
  ["revoke select on table pg_catalog.pg_stat_database_conflicts from public;", "grant select on table pg_catalog.pg_stat_database_conflicts to public;"],
  ["ALTER ROUTINE s.f(integer) SET search_path = s, pg_temp;", "ALTER ROUTINE s.f(integer) RESET search_path;"],
  ["ALTER ROUTINE \"S\".\"f x\"(integer, text[]) SET search_path = \"S\", pg_temp;", "ALTER ROUTINE \"S\".\"f x\"(integer, text[]) SET search_path = public, \"x y\";"],
  ["REVOKE TEMPORARY ON DATABASE d FROM PUBLIC;", "GRANT TEMPORARY ON DATABASE d TO PUBLIC;"],
  ["ALTER ROUTINE s.f(character varying, public.mytype, \"My Type\"[]) SET search_path = \"\$user\", pg_temp;", "ALTER ROUTINE s.f(character varying, public.mytype, \"My Type\"[]) SET search_path = \"\$user\", public;"],
];
$refusedPairs = [
  'catalog table outside the list (pg_authid)' => ["REVOKE SELECT ON TABLE pg_catalog.pg_authid FROM PUBLIC;", "GRANT SELECT ON TABLE pg_catalog.pg_authid TO PUBLIC;"],
  'GRANT as the way back to pg_authid' => ["REVOKE SELECT ON TABLE pg_catalog.pg_database FROM PUBLIC;", "GRANT SELECT ON TABLE pg_catalog.pg_authid TO PUBLIC;"],
  'privilege other than SELECT on a catalog' => ["REVOKE ALL ON TABLE pg_catalog.pg_database FROM PUBLIC;", "GRANT ALL ON TABLE pg_catalog.pg_database TO PUBLIC;"],
  'UPDATE on a catalog' => ["REVOKE SELECT ON TABLE pg_catalog.pg_database FROM PUBLIC;", "GRANT UPDATE ON TABLE pg_catalog.pg_database TO PUBLIC;"],
  'REVOKE on pg_class' => ["REVOKE SELECT ON TABLE pg_catalog.pg_class FROM PUBLIC;", "GRANT SELECT ON TABLE pg_catalog.pg_class TO PUBLIC;"],
  'prefix of an allowed name (pg_roles_x)' => ["REVOKE SELECT ON TABLE pg_catalog.pg_roles_x FROM PUBLIC;", "GRANT SELECT ON TABLE pg_catalog.pg_roles_x TO PUBLIC;"],
  'quoted catalog name' => ["REVOKE SELECT ON TABLE pg_catalog.\"pg_database\" FROM PUBLIC;", "GRANT SELECT ON TABLE pg_catalog.\"pg_database\" TO PUBLIC;"],
  'other schema' => ["REVOKE SELECT ON TABLE public.pg_database FROM PUBLIC;", "GRANT SELECT ON TABLE public.pg_database TO PUBLIC;"],
  'a role instead of PUBLIC' => ["REVOKE SELECT ON TABLE pg_catalog.pg_database FROM x;", "GRANT SELECT ON TABLE pg_catalog.pg_database TO x;"],
  'second statement' => ["REVOKE SELECT ON TABLE pg_catalog.pg_database FROM PUBLIC; DROP TABLE t;", "GRANT SELECT ON TABLE pg_catalog.pg_database TO PUBLIC;"],
  'rollback is not the inverse (other object)' => ["REVOKE SELECT ON TABLE pg_catalog.pg_database FROM PUBLIC;", "GRANT SELECT ON TABLE pg_catalog.pg_roles TO PUBLIC;"],
  'rollback is not the inverse (more objects)' => ["REVOKE SELECT ON TABLE pg_catalog.pg_database FROM PUBLIC;", "GRANT SELECT ON TABLE $cat TO PUBLIC;"],
  'database privilege widened in the way back' => ["REVOKE CONNECT ON DATABASE d FROM PUBLIC;", "GRANT ALL ON DATABASE d TO PUBLIC;"],
  'GRANT as the fix' => ["GRANT SELECT ON TABLE pg_catalog.pg_database TO PUBLIC;", "REVOKE SELECT ON TABLE pg_catalog.pg_database FROM PUBLIC;"],
  'ALTER fix with a GRANT way back' => ["ALTER ROUTINE s.f() SET search_path = s, pg_temp;", "GRANT ALL ON SCHEMA s TO PUBLIC;"],
  'newline inside' => ["REVOKE SELECT ON TABLE pg_catalog.pg_database\nFROM PUBLIC;", "GRANT SELECT ON TABLE pg_catalog.pg_database TO PUBLIC;"],
  'null' => [null, null],
  'ALL on pg_catalog schema' => ["REVOKE ALL ON SCHEMA pg_catalog FROM PUBLIC;", "GRANT ALL ON SCHEMA pg_catalog TO PUBLIC;"],
  'USAGE on pg_catalog schema' => ["REVOKE USAGE ON SCHEMA pg_catalog FROM PUBLIC;", "GRANT USAGE ON SCHEMA pg_catalog TO PUBLIC;"],
  'USAGE on information_schema (quoted)' => ["REVOKE USAGE ON SCHEMA \"information_schema\" FROM PUBLIC;", "GRANT USAGE ON SCHEMA \"information_schema\" TO PUBLIC;"],
  'ALL PRIVILEGES on a database' => ["REVOKE ALL PRIVILEGES ON DATABASE d FROM PUBLIC;", "GRANT ALL PRIVILEGES ON DATABASE d TO PUBLIC;"],
  'object list instead of one object' => ["REVOKE CONNECT ON SCHEMA a, pg_catalog FROM PUBLIC;", "GRANT CONNECT ON SCHEMA a, pg_catalog TO PUBLIC;"],
  'quoted names differing in case' => ["REVOKE CREATE ON SCHEMA \"Foo\" FROM PUBLIC;", "GRANT CREATE ON SCHEMA \"foo\" TO PUBLIC;"],
  'quoted names differing in spaces' => ["REVOKE CREATE ON SCHEMA \"a  b\" FROM PUBLIC;", "GRANT CREATE ON SCHEMA \"a b\" TO PUBLIC;"],
  'way back on another database' => ["REVOKE CONNECT ON DATABASE a FROM PUBLIC;", "GRANT CONNECT ON DATABASE b TO PUBLIC;"],
  'ALTER with LEAKPROOF' => ["ALTER FUNCTION s.f() LEAKPROOF SET search_path = a;", "ALTER FUNCTION s.f() RESET search_path;"],
  'ALTER with a second action' => ["ALTER FUNCTION s.f() SET search_path = a SET role = postgres;", "ALTER FUNCTION s.f() RESET search_path;"],
  'ALTER way back on another routine' => ["ALTER ROUTINE s.f() SET search_path = a;", "ALTER ROUTINE s.g() RESET search_path;"],
  'ALTER on pg_catalog routine as way back' => ["ALTER ROUTINE s.f() SET search_path = a;", "ALTER ROUTINE pg_catalog.pg_read_file(text) RESET search_path;"],
  'ALTER on pg_catalog routine as the fix' => ["ALTER ROUTINE pg_catalog.pg_read_file(text) SET search_path = x, pg_temp;", "ALTER ROUTINE pg_catalog.pg_read_file(text) RESET search_path;"],
  'ALTER on information_schema routine' => ["ALTER ROUTINE information_schema.f() SET search_path = x, pg_temp;", "ALTER ROUTINE information_schema.f() RESET search_path;"],
  'ALTER on quoted pg_toast routine' => ["ALTER ROUTINE \"pg_toast\".f() SET search_path = x, pg_temp;", "ALTER ROUTINE \"pg_toast\".f() RESET search_path;"],
  'ALTER fix that is a RESET' => ["ALTER ROUTINE s.f() RESET search_path;", "ALTER ROUTINE s.f() RESET search_path;"],
  'ALTER fix without pg_temp last' => ["ALTER ROUTINE s.f() SET search_path = public;", "ALTER ROUTINE s.f() RESET search_path;"],
  'non-string journal value' => [['x'], 5],
  'huge statement' => ["REVOKE CREATE ON SCHEMA " . str_repeat('a', 9000) . " FROM PUBLIC;", "GRANT CREATE ON SCHEMA a TO PUBLIC;"],
];
$failed = 0;
// The allowlist names and the names in rule db.catalog_visibility must not drift apart (a drift silently skips the fix).
$rules = json_decode((string) file_get_contents(__DIR__ . '/../rules/postgresql.json'), true, 512, JSON_THROW_ON_ERROR)['rules'];
foreach ($rules as $r) {
  if ($r['id'] === 'db.catalog_visibility') {
    preg_match("/c\.relname IN \(([^)]*)\)/", $r['check']['sql'], $m);
    $inRule = array_map(static fn($x) => trim($x, " '"), explode(',', $m[1] ?? ''));
    $inCode = ServerFiles::CATALOG_NAMES;
    sort($inRule);
    sort($inCode);
    if ($inRule !== $inCode) {
      echo "FAIL: names in rule db.catalog_visibility differ from ServerFiles::CATALOG_NAMES
";
      $failed++;
    }
  }
}
foreach ($allowedPairs as $i => [$fix, $rollback]) {
  if (!ServerFiles::pairAllowed($fix, $rollback)) {
    echo "FAIL (should be allowed) #$i: $fix\n";
    $failed++;
  }
}
foreach ($refusedPairs as $why => [$fix, $rollback]) {
  if (ServerFiles::pairAllowed($fix, $rollback)) {
    echo "FAIL (should be refused) $why\n";
    $failed++;
  }
}
echo $failed === 0 ? 'OK: ' . (count($allowedPairs) + count($refusedPairs)) . " cases\n" : "$failed failure(s)\n";
exit($failed === 0 ? 0 : 1);
