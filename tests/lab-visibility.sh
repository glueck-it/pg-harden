#!/bin/sh
# Catalog visibility experiment (rule db.catalog_visibility): what does REVOKE SELECT on name-carrying catalogs
# from PUBLIC hide, and what breaks? Runs inside a throw-away PostgreSQL container (psql, createdb, pg_dump present,
# trust authentication on the local socket). Prints one verdict line per probe; compare across versions.
# Usage: docker exec -i <container> sh < tests/lab-visibility.sh
[ "${PGHARDEN_LAB:-}" = 1 ] || { echo "Nur in einem Wegwerf-Container: PGHARDEN_LAB=1 setzen (das Skript ändert Passwörter, Rollen und Datenbanken)." >&2; exit 2; }
unset PGHOST PGPORT PGSERVICE PGDATABASE
PSQL="psql -U postgres -X -q -v ON_ERROR_STOP=1"
OBJECTS="pg_database pg_roles pg_user pg_group pg_auth_members pg_stat_database pg_stat_database_conflicts pg_shdescription"
say() { printf '%-46s %s\n' "$1" "$2"; }
# runs a command as role $1 against database $2 and reports ok/denied/other (first error line, shortened)
as() { who=$1; db=$2; shift 2; out=$(psql -U "$who" -d "$db" -X -At "$@" 2>&1); rc=$?
       if [ $rc -eq 0 ]; then echo "ok"; else echo "FEHLER: $(echo "$out" | head -1 | cut -c1-70)"; fi; }
count() { who=$1; db=$2; shift 2; psql -U "$who" -d "$db" -X -At "$@" 2>&1 | head -1 | cut -c1-70; }

$PSQL -d postgres <<'EOF'
DROP DATABASE IF EXISTS da; DROP DATABASE IF EXISTS db_b; DROP DATABASE IF EXISTS dn; DROP DATABASE IF EXISTS dn0;
DROP ROLE IF EXISTS ra; DROP ROLE IF EXISTS rb; DROP ROLE IF EXISTS rbackup;
CREATE ROLE ra LOGIN; CREATE ROLE rb LOGIN; CREATE ROLE rbackup LOGIN;
CREATE DATABASE da OWNER ra; CREATE DATABASE db_b OWNER rb;
REVOKE CONNECT ON DATABASE da FROM PUBLIC; REVOKE CONNECT ON DATABASE db_b FROM PUBLIC; REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
GRANT CONNECT ON DATABASE da TO ra, rbackup; GRANT CONNECT ON DATABASE db_b TO rb; GRANT CONNECT ON DATABASE postgres TO ra, rb;
EOF
echo "== Ausgangslage (nur CONNECT entzogen)"
say "ra sieht Datenbanken in pg_database" "$(count ra da -c 'select count(*) from pg_database')"
say "ra sieht Rollen in pg_roles" "$(count ra da -c 'select count(*) from pg_roles')"

# the fix: in template1 and in every connectable database (the ACL of a shared catalog lives in each database's pg_class)
for d in $(psql -U postgres -X -At -d postgres -c "select datname from pg_database where datname <> 'template0'"); do
  for o in $OBJECTS; do $PSQL -d "$d" -c "REVOKE SELECT ON TABLE pg_catalog.$o FROM PUBLIC" || echo "Fix fehlgeschlagen: $d.$o"; done
done
echo "== Nach REVOKE (in allen Datenbanken außer template0)"
say "select * from pg_database" "$(as ra da -c 'select 1 from pg_database limit 1')"
say "select * from pg_roles" "$(as ra da -c 'select 1 from pg_roles limit 1')"
say "select * from pg_user" "$(as ra da -c 'select 1 from pg_user limit 1')"
say "select * from pg_stat_database" "$(as ra da -c 'select 1 from pg_stat_database limit 1')"
say "select * from pg_auth_members" "$(as ra da -c 'select 1 from pg_auth_members limit 1')"
say "psql \\l" "$(as ra da -c '\l')"
say "psql \\du" "$(as ra da -c '\du')"
say "psql \\dn \\dt \\df \\dp \\d" "$(as ra da -c '\dn' -c '\dt' -c '\df' -c '\dp' -c '\d')"
say "createdb (Recht fehlt ohnehin)" "$(as ra postgres -c 'select 1' >/dev/null; createdb -U ra x_ra 2>&1 | head -1 | cut -c1-70)"
say "pg_dump als Eigentümer ra" "$(pg_dump -U ra da 2>&1 >/dev/null | head -1 | cut -c1-70)"
say "pg_dump als Superuser" "$(pg_dump -U postgres da 2>&1 >/dev/null | head -1 | cut -c1-70)"
say "pg_dumpall --globals-only als Superuser" "$(pg_dumpall -U postgres --globals-only 2>&1 >/dev/null | head -1 | cut -c1-70)"
say "Verbinden mit db_b (kein CONNECT)" "$(psql -U ra -d db_b -X -Atc 'select 1' 2>&1 | sed -n 's/.*FATAL: *//p' | head -1)"
say "Verbinden mit nicht vorhandener Datenbank" "$(psql -U ra -d nichtda -X -Atc 'select 1' 2>&1 | sed -n 's/.*FATAL: *//p' | head -1)"
say "Rollenname über oid::regrole ermittelbar" "$(count ra da -c "select count(*) from generate_series(1,70000) g where g::oid::regrole::text !~ '^[0-9]+\$'")"
# a foreign session of rb on db_b, observed by ra
psql -U rb -d db_b -X -Atc "select pg_sleep(15)" >/dev/null 2>&1 &
sleep 2
say "pg_stat_activity: ra sieht Sitzung von rb in db_b (Zeilen)" "$(count ra da -c "select count(*) from pg_stat_activity where datname = 'db_b'")"

echo "== Gefilterte Sicht (Ansicht des Superusers in eigenem Schema, in der Datenbank postgres)"
$PSQL -d postgres <<'EOF2'
CREATE SCHEMA IF NOT EXISTS visibility; GRANT USAGE ON SCHEMA visibility TO PUBLIC;
CREATE OR REPLACE VIEW visibility.databases WITH (security_barrier = true) AS SELECT d.datname FROM pg_catalog.pg_database d WHERE NOT d.datistemplate AND pg_catalog.has_database_privilege(d.datname, 'CONNECT');
CREATE OR REPLACE VIEW visibility.databases_leaky AS SELECT d.datname FROM pg_catalog.pg_database d WHERE NOT d.datistemplate AND pg_catalog.has_database_privilege(d.datname, 'CONNECT');
GRANT SELECT ON visibility.databases, visibility.databases_leaky TO PUBLIC;
EOF2
say "ra: visibility.databases" "$(psql -U ra -d postgres -X -At -c 'select string_agg(datname, $$,$$ order by datname) from visibility.databases' 2>&1 | head -1)"
say "rb: visibility.databases" "$(psql -U rb -d postgres -X -At -c 'select string_agg(datname, $$,$$ order by datname) from visibility.databases' 2>&1 | head -1)"

# a function ra supplies as a filter must not see the rows the view hides (security_barrier)
$PSQL -d postgres -c "CREATE DATABASE geheim_kunde_x"
$PSQL -d postgres -c "REVOKE CONNECT ON DATABASE geheim_kunde_x FROM PUBLIC"
for v in databases databases_leaky; do
  seen=$(psql -U ra -d postgres -X -q 2>&1 <<EOF3 | grep -c "gesehen: geheim_kunde_x"
CREATE FUNCTION pg_temp.spy(text) RETURNS boolean LANGUAGE plpgsql COST 0.0001 AS \$\$ BEGIN RAISE NOTICE 'gesehen: %', \$1; RETURN true; END \$\$;
SELECT count(*) FROM visibility.$v WHERE pg_temp.spy(datname);
EOF3
)
  say "ra: Filterfunktion sieht verborgenen Namen über visibility.$v" "$seen (0 = dicht)"
done

echo "== Neue Datenbanken"
$PSQL -d postgres -c "CREATE DATABASE dn TEMPLATE template1" -c "CREATE DATABASE dn0 TEMPLATE template0"
say "aus template1: PUBLIC darf pg_database lesen?" "$(psql -U postgres -X -At -d dn -c "select has_table_privilege('public','pg_database','select')")"
say "aus template0: PUBLIC darf pg_database lesen?" "$(psql -U postgres -X -At -d dn0 -c "select has_table_privilege('public','pg_database','select')")"

echo "== Dump trägt den Entzug"
say "pg_dumpall: REVOKE-Zeilen für pg_database" "$(pg_dumpall -U postgres 2>/dev/null | grep -c 'REVOKE SELECT ON TABLE pg_catalog.pg_database FROM PUBLIC')"
say "Datenbanken im Dump (ohne template0)" "$(psql -U postgres -X -At -d postgres -c "select count(*) from pg_database where datname <> 'template0'")"
say "pg_init_privs unverändert (Ausgangswert PUBLIC=r)" "$(psql -U postgres -X -At -d da -c "select initprivs::text from pg_init_privs where objoid = 'pg_database'::regclass")"

echo "== Gezielte Freigabe und Rückweg"
$PSQL -d da -c "GRANT SELECT ON TABLE pg_catalog.pg_roles, pg_catalog.pg_database TO rbackup"
say "rbackup mit GRANT auf pg_roles+pg_database: pg_dump da" "$(pg_dump -U rbackup da 2>&1 >/dev/null | head -1 | cut -c1-70)"
for d in $(psql -U postgres -X -At -d postgres -c "select datname from pg_database where datname <> 'template0'"); do
  for o in $OBJECTS; do $PSQL -d "$d" -c "GRANT SELECT ON TABLE pg_catalog.$o TO PUBLIC"; done
done
say "nach Rückweg: ra liest pg_database" "$(as ra da -c 'select 1 from pg_database limit 1')"
say "nach Rückweg: relacl wieder dem Ausgangswert gleich?" "$(psql -U postgres -X -At -d da -c "select coalesce(relacl::text,'NULL') from pg_class where oid = 'pg_database'::regclass")"
