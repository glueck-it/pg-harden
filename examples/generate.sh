#!/bin/sh
# Erzeugt die Beispielausgaben in examples/output/ mit einem Wegwerf-Container (PostgreSQL 18, Debian).
# Aufruf aus dem Werkzeugverzeichnis (Git Bash unter Windows: MSYS_NO_PATHCONV=1):  sh examples/generate.sh
# Braucht Docker und Internetzugang (apt im Container). Der Container lauscht nur auf 127.0.0.1 und wird danach gelöscht.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
TOOL=$(dirname "$HERE")
OUT="$HERE/output"
NAME=pgharden-examples
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
cleanup
rm -rf "$OUT" && mkdir -p "$OUT"
# docker cp needs a native path (Git Bash on Windows: pwd -W)
OUTD=$(cd "$OUT" && (pwd -W 2>/dev/null || pwd))

docker run -d --name "$NAME" -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_INITDB_ARGS=--no-data-checksums \
  postgres:18-trixie -c listen_addresses=127.0.0.1 >/dev/null
i=0; ok=0
while [ $i -lt 90 ]; do
  sleep 1; i=$((i + 1))
  if docker exec "$NAME" pg_isready -q -h 127.0.0.1 -U postgres; then ok=$((ok + 1)); else ok=0; fi
  [ $ok -ge 2 ] && break
done
docker exec "$NAME" sh -c 'apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq php-cli php-pgsql php-mbstring >/dev/null 2>&1; command -v php >/dev/null'
docker exec -i "$NAME" psql -U postgres -X -q -v ON_ERROR_STOP=1 < "$HERE/sample-init.sql"
docker exec "$NAME" mkdir -p /opt/pg-harden
(cd "$TOOL" && for f in pg-harden.php src rules mappings; do docker cp "$f" "$NAME:/opt/pg-harden/"; done)

run() { docker exec "$NAME" sh -c "cd /opt/pg-harden && $1" || true; }
H="--host=127.0.0.1 --user=postgres"

run "php pg-harden.php check $H" > "$OUT/01-check.txt"
run "php pg-harden.php check $H --format=html" > "$OUT/01-check.html"
run "php pg-harden.php plan $H --dir=/root/plan" > "$OUT/02-plan.txt"
docker cp "$NAME:/root/plan" "$OUTD/02-plan"
run "php pg-harden.php apply $H --include-confirm=db.public_schema_create,code.secdef_search_path" > "$OUT/03-apply-dry-run.txt"
run "php pg-harden.php apply $H --include-confirm=db.public_schema_create,code.secdef_search_path --execute --yes --dir=/root/journal" > "$OUT/04-apply.txt"
docker cp "$NAME:/root/journal/apply-log.json" "$OUTD/04-apply-log.json"
run "ls -la /root/journal /root/journal/backup" > "$OUT/04-journal-files.txt"
run "cat \$(psql -U postgres -Atc 'show data_directory')/conf.d/90-pg-harden.conf" > "$OUT/04-written-90-pg-harden.conf"
run "php pg-harden.php verify $H --previous=/root/plan/report.json" > "$OUT/05-verify.txt"
run "php pg-harden.php verify $H --previous=/root/plan/report.json --format=html" > "$OUT/05-verify.html"
run "php pg-harden.php rollback $H --dir=/root/journal" > "$OUT/06-rollback.txt"
# Lockout protection: pg_hba.conf trust -> scram-sha-256 is refused while login roles have no SCRAM password
run "sha256sum \$(psql -U postgres -Atc 'show hba_file')" > "$OUT/07-pg_hba-checksum-before.txt"
run "php pg-harden.php apply $H --rules=hba.trust --include-confirm=hba.trust --execute --yes --dir=/root/journal-hba" > "$OUT/07-apply-hba-refused.txt"
run "sha256sum \$(psql -U postgres -Atc 'show hba_file')" > "$OUT/07-pg_hba-checksum-after.txt"
run "php pg-harden.php rules" > "$OUT/08-rules.txt"
run "php pg-harden.php client" > "$OUT/09-client.txt"
run "php pg-harden.php client --format=html" > "$OUT/09-client.html"
echo "Ausgaben in $OUT"
