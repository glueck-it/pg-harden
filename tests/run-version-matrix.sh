#!/bin/sh
# Version matrix: one throw-away container per PostgreSQL image, PHP installed inside, then
#   1. check -o /tmp/check.json       -> <out>/<tag>.check.json   (rule status per version)
#   2. tests/lab-matrix.sh            -> <out>/<tag>.matrix.txt   (apply/rollback regression)
#   3. tests/lab-visibility.sh        -> <out>/<tag>.visibility.txt (in a second, pristine container)
# Usage (from the tool directory; Git Bash on Windows needs MSYS_NO_PATHCONV=1):
#   sh tests/run-version-matrix.sh <out-dir> 14-trixie 15-trixie 16-trixie 17-trixie 18-trixie 19rc1
# Needs Docker and internet access (apt inside the container). The Debian images are required (apt).
# The containers listen on 127.0.0.1 only and use trust authentication — throw-away lab instances, nothing else.
OUT=$1; shift
[ -n "$OUT" ] && [ $# -gt 0 ] || { echo "usage: $0 <out-dir> <image-tag>..." >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
TOOL=$(dirname "$HERE")
mkdir -p "$OUT"
NAME=
cleanup() { [ -n "$NAME" ] && docker rm -f "$NAME" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

# start_container <tag>: fresh container, waits until the real server (not the init-time server) accepts TCP connections
start_container() {
  NAME="pgm_$(echo "$1" | tr -c 'a-zA-Z0-9\n' _)"
  docker rm -f "$NAME" >/dev/null 2>&1
  docker run -d --name "$NAME" -e POSTGRES_HOST_AUTH_METHOD=trust "postgres:$1" -c listen_addresses=127.0.0.1 >/dev/null || return 1
  i=0; ok=0
  while [ $i -lt 90 ]; do
    sleep 1; i=$((i + 1))
    if docker exec "$NAME" pg_isready -q -h 127.0.0.1 -U postgres; then ok=$((ok + 1)); else ok=0; fi
    [ $ok -ge 2 ] && return 0
  done
  echo "Server in $NAME wurde nicht bereit" >&2
  return 1
}

for tag in "$@"; do
  start_container "$tag" || { echo "== $tag: Container nicht startbar — übersprungen" >&2; continue; }
  echo "== $tag: $(docker exec "$NAME" psql -U postgres -Atc 'show server_version')"
  docker exec "$NAME" sh -c 'apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq php-cli php-pgsql php-mbstring >/dev/null 2>&1'
  docker exec "$NAME" sh -c 'command -v php >/dev/null && php -v | head -1' || { echo "php fehlt in $tag — übersprungen" >&2; cleanup; continue; }
  docker exec "$NAME" mkdir -p /opt/pgh
  (cd "$TOOL" && docker cp pg-harden.php "$NAME:/opt/pgh/" && docker cp src "$NAME:/opt/pgh/" && docker cp rules "$NAME:/opt/pgh/" \
    && docker cp mappings "$NAME:/opt/pgh/" && docker cp tests "$NAME:/opt/pgh/") || { echo "Kopieren fehlgeschlagen — $tag übersprungen" >&2; cleanup; continue; }
  docker exec "$NAME" sh -c 'cp /opt/pgh/tests/scram.sql /tmp/scram.sql'
  docker exec "$NAME" sh -c 'cd /opt/pgh && php pg-harden.php check --host=127.0.0.1 --user=postgres --sslmode=disable -o /tmp/check.json > /dev/null 2>/tmp/check.err; echo "check exit=$?"'
  docker cp "$NAME:/tmp/check.json" "$OUT/$tag.check.json"
  docker cp "$NAME:/tmp/check.err" "$OUT/$tag.check.err"
  docker exec -e PGHARDEN_LAB=1 "$NAME" sh -c 'TOOL=/opt/pgh sh /opt/pgh/tests/lab-matrix.sh' > "$OUT/$tag.matrix.txt" 2>&1
  # the visibility test creates roles and databases: run it in a second, pristine container
  start_container "$tag" || { echo "== $tag: zweiter Container nicht startbar" >&2; continue; }
  docker exec -i -e PGHARDEN_LAB=1 "$NAME" sh < "$HERE/lab-visibility.sh" 2>&1 | grep -v NOTICE > "$OUT/$tag.visibility.txt"
  cleanup
done
