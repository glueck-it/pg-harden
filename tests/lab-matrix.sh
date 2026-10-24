#!/bin/sh
# Regression matrix for apply/rollback inside a PostgreSQL container (Linux, as root, PHP installed).
# Usage: TOOL=/opt/pgh sh tests/lab-matrix.sh   (needs tests/scram.sql at /tmp/scram.sql; trust authentication as in lab/)
# Prints only the verdict lines; compare them with the expectations in the "say" headings.
[ "${PGHARDEN_LAB:-}" = 1 ] || { echo "Nur in einem Wegwerf-Container: PGHARDEN_LAB=1 setzen (das Skript ändert Passwörter, Rollen und Datenbanken)." >&2; exit 2; }
unset PGHOST PGPORT PGSERVICE PGDATABASE
cd "${TOOL:-/opt/pgh}" || exit 1
D=$(psql -U postgres -Atc "show data_directory")
H="--host=127.0.0.1 --user=postgres"
say() { printf '\n### %s\n' "$1"; }
sumry() { sed -n '/== Ergebnis/,/== Vergleich/p' "$1" | grep -v '^==' | grep -v '^$' | cut -c1-170; }

say "T1 conf apply (include_dir wird ergänzt, conf.d mit Besitzer postgres)"
rm -rf /tmp/m1; php pg-harden.php apply $H --execute --yes --dir=/tmp/m1 > /tmp/m1.out 2>&1; echo "exit=$?"; sumry /tmp/m1.out
ls -ld $D/conf.d | cut -c1-60; ls -l $D/conf.d | tail -1 | cut -c1-70
grep -c "include_dir = 'conf.d'" $D/postgresql.conf

say "T2 rollback of T1"
php pg-harden.php rollback $H --dir=/tmp/m1 2>&1 | head -6 | cut -c1-150
grep -c "include_dir = 'conf.d'" $D/postgresql.conf; ls $D/conf.d 2>&1 | head -2

say "T3 rollback twice is refused"
php pg-harden.php rollback $H --dir=/tmp/m1 2>&1 | head -2

say "T4 SCRAM roles for hba tests"
psql -U postgres -v ON_ERROR_STOP=1 -f /tmp/scram.sql >/dev/null && echo roles-ok

say "T5 hba.trust without password -> lockout is reverted"
md5sum $D/pg_hba.conf | cut -c1-32
rm -rf /tmp/m5; php pg-harden.php apply $H --include-confirm=hba.trust --execute --yes --dir=/tmp/m5 > /tmp/m5.out 2>&1; echo "exit=$?"; sumry /tmp/m5.out
md5sum $D/pg_hba.conf | cut -c1-32

say "T6 hba.trust with password + rollback"
rm -rf /tmp/m6; PGPASSWORD=Test-pw-1 php pg-harden.php apply $H --include-confirm=hba.trust --execute --yes --dir=/tmp/m6 > /tmp/m6.out 2>&1; echo "exit=$?"; sumry /tmp/m6.out
grep -c "scram-sha-256" $D/pg_hba.conf
PGPASSWORD=Test-pw-1 php pg-harden.php rollback $H --dir=/tmp/m6 2>&1 | head -5 | cut -c1-150
md5sum $D/pg_hba.conf | cut -c1-32

say "T7 SQL apply + rollback"
rm -rf /tmp/m7; php pg-harden.php apply $H --include-confirm=db.public_schema_create,db.public_temp,code.secdef_search_path --execute --yes --dir=/tmp/m7 > /tmp/m7.out 2>&1; echo "exit=$?"; sumry /tmp/m7.out | head -8
php pg-harden.php rollback $H --dir=/tmp/m7 2>&1 | head -7 | cut -c1-150

say "T8 tampered journal: path outside the server's files is refused"
rm -rf /tmp/m8; php pg-harden.php apply $H --execute --yes --dir=/tmp/m8 > /dev/null 2>&1
sed -i "s#\"path\": \"$D/postgresql.conf\"#\"path\": \"/etc/passwd\"#" /tmp/m8/apply-log.json
php pg-harden.php rollback $H --dir=/tmp/m8 2>&1 | head -2 | cut -c1-200
chmod 0755 /tmp/m8; php pg-harden.php rollback $H --dir=/tmp/m8 2>&1 | head -1 | cut -c1-200

say "T9 --help wins over --execute"
php pg-harden.php apply --help --execute 2>&1 | head -1 | cut -c1-80

say "T10 unverified remote channel is refused for writing"
php pg-harden.php apply --host=db.example.invalid --user=postgres --execute --yes --dir=/tmp/m10 2>&1 | head -1 | cut -c1-220

say "T11 catalog visibility: apply revokes in every database incl. template1, rollback restores"
rm -rf /tmp/m11; php pg-harden.php apply $H --include-confirm=db.catalog_visibility --execute --yes --dir=/tmp/m11 > /tmp/m11.out 2>&1; echo "exit=$?"; sumry /tmp/m11.out | head -8
psql -U postgres -d postgres -c "create database t11new" >/dev/null
for d in $(psql -U postgres -Atc "select datname from pg_database where datname <> 'template0'"); do printf 'nach apply %s: PUBLIC liest pg_database=%s
' "$d" "$(psql -U postgres -d "$d" -Atc "select has_table_privilege('public','pg_database','select')")"; done
php pg-harden.php rollback $H --dir=/tmp/m11 2>&1 | head -8 | cut -c1-150
for d in $(psql -U postgres -Atc "select datname from pg_database where datname <> 'template0' and datname <> 't11new'"); do printf 'nach rollback %s: PUBLIC liest pg_database=%s
' "$d" "$(psql -U postgres -d "$d" -Atc "select has_table_privilege('public','pg_database','select')")"; done
