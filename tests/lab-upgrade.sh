#!/bin/sh
# Does the catalog REVOKE (rule db.catalog_visibility) survive pg_upgrade? Old cluster = OLD major, new cluster = the image's major.
# Runs in a throw-away Debian PostgreSQL image (postgres:N-trixie, PGDG apt repository present), as root; clusters live in /tmp.
# Usage: docker run -d --name up -e POSTGRES_HOST_AUTH_METHOD=trust postgres:18-trixie
#        docker exec -i -e OLD=17 -e PGHARDEN_LAB=1 up sh < tests/lab-upgrade.sh
[ "${PGHARDEN_LAB:-}" = 1 ] || { echo "Nur in einem Wegwerf-Container: PGHARDEN_LAB=1 setzen (das Skript ändert Passwörter, Rollen und Datenbanken)." >&2; exit 2; }
unset PGHOST PGPORT PGSERVICE PGDATABASE
OLD=${OLD:-17}
NEW=$(ls /usr/lib/postgresql | sort -n | tail -1)
[ "$OLD" != "$NEW" ] || { echo "OLD und NEW sind gleich ($OLD)"; exit 2; }
OBJECTS="pg_database, pg_roles, pg_user, pg_group, pg_auth_members, pg_stat_database, pg_stat_database_conflicts, pg_shdescription"
apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "postgresql-$OLD" >/dev/null 2>&1 || { echo "postgresql-$OLD nicht installierbar"; exit 2; }
OB=/usr/lib/postgresql/$OLD/bin; NB=/usr/lib/postgresql/$NEW/bin
rm -rf /tmp/up && mkdir -p /tmp/up && chown postgres /tmp/up
run() { su postgres -c "$1"; }
run "$OB/initdb -D /tmp/up/old -A trust -U postgres >/dev/null && $NB/initdb -D /tmp/up/new -A trust -U postgres --no-data-checksums >/dev/null"
run "$OB/pg_ctl -D /tmp/up/old -o '-p 5433 -k /tmp/up' -l /tmp/up/old.log -w start >/dev/null"
P="psql -h /tmp/up -p 5433 -U postgres -X -At -v ON_ERROR_STOP=1"
run "$P -d postgres -c 'create database da' -c 'create database db_b' -c 'create role ra login'"
for d in template1 postgres da db_b; do run "$P -d $d -c 'REVOKE SELECT ON TABLE $(echo "$OBJECTS" | sed 's/pg_/pg_catalog.pg_/g') FROM PUBLIC'"; done
echo "alt ($OLD): PUBLIC liest pg_database in template1/da: $(run "$P -d template1 -c \"select has_table_privilege('public','pg_database','select')\"") / $(run "$P -d da -c \"select has_table_privilege('public','pg_database','select')\"")"
run "$OB/pg_ctl -D /tmp/up/old -w stop >/dev/null"
run "cd /tmp/up && $NB/pg_upgrade -b $OB -B $NB -d /tmp/up/old -D /tmp/up/new >/tmp/up/upgrade.out 2>&1"; rc=$?; echo "pg_upgrade exit=$rc"
tail -3 /tmp/up/upgrade.out
[ $rc -eq 0 ] || exit 1
run "$NB/pg_ctl -D /tmp/up/new -o '-p 5434 -k /tmp/up' -l /tmp/up/new.log -w start >/dev/null"
P="psql -h /tmp/up -p 5434 -U postgres -X -At -v ON_ERROR_STOP=1"
for d in template1 postgres da db_b; do
  echo "neu ($NEW) $d: PUBLIC liest pg_database=$(run "$P -d $d -c \"select has_table_privilege('public','pg_database','select')\""), pg_roles=$(run "$P -d $d -c \"select has_table_privilege('public','pg_roles','select')\"")"
done
echo "neu: Datenbank aus template1 neu angelegt erbt den Entzug: $(run "$P -d postgres -c 'create database dn'" >/dev/null; run "$P -d dn -c \"select has_table_privilege('public','pg_database','select')\"")"
# restore: pg_dumpall of the upgraded cluster into a fresh cluster of the same major
run "$NB/initdb -D /tmp/up/res -A trust -U postgres --no-data-checksums >/dev/null && $NB/pg_ctl -D /tmp/up/res -o '-p 5435 -k /tmp/up' -l /tmp/up/res.log -w start >/dev/null"
run "$NB/pg_dumpall -h /tmp/up -p 5434 -U postgres > /tmp/up/all.sql"
run "psql -h /tmp/up -p 5435 -U postgres -X -q -d postgres -f /tmp/up/all.sql >/dev/null 2>&1"
P="psql -h /tmp/up -p 5435 -U postgres -X -At"
for d in template1 postgres da db_b; do
  echo "Restore ($NEW) $d: PUBLIC liest pg_database=$(run "$P -d $d -c \"select has_table_privilege('public','pg_database','select')\""), pg_roles=$(run "$P -d $d -c \"select has_table_privilege('public','pg_roles','select')\"")"
done
run "$NB/pg_ctl -D /tmp/up/res -w stop >/dev/null"
run "$NB/pg_ctl -D /tmp/up/new -w stop >/dev/null"
