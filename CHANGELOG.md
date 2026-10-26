# Changelog

## Unreleased

- **Security fix for `check` and `client` run as root.** Affected: 0.3.1 and earlier on Linux and other Unix systems; reproduced
  against 0.3.1 in a test container. Both commands read files that another account controls, and they read them as root:
  - `client --user=<account>`: the account could link its `.pgpass` (or a service file, certificate or script) to a file only root may
    read — the report then showed findings from root's file as the account's own (places and kinds of finding; values are not printed).
  - `check`: the service account could write any process number into `postmaster.pid`; the process probes then read the environment
    (names of variables containing `PASSWORD`), the owner and the program file of that other process as root and reported them as the
    server's. A FIFO in place of `postmaster.pid` made `check` hang without end.

  The way it works now: such files are read with the identity of the account that controls the way to them (the same walk from `/` as
  for writing). A directory of root that group or others can write — for example `/tmp` — is not refused for reading: with the sticky
  bit an existing entry decides by its owner (a file or link of root there is read as `nobody`, since anybody may have placed a hard link
  to it), otherwise the file is read as `nobody`. Every read opens without blocking and accepts only a regular file within a size limit. The process number counts only when
  it is the parent of the tool's own database connection; on Linux both processes must also run as the owner of the data directory and
  the start time must match the server's (`/proc`), on Windows the parent is checked in the process list. Otherwise the process probes
  report "nicht geprüft". Windows has no identity switch: whether a junction on the way can redirect a read of `client --user` or a write
  of `apply` there is examined next. Tests in `tests/lab-identity.php` (T14); checked against PostgreSQL 18 on Alpine and on Windows 11.

## 0.3.1 (2026-10-25)

- **Security fix — update if you run `apply` or `rollback` as root.** Affected: 0.3.0 on Linux and other Unix systems, `apply --execute`
  run as root (`rollback` of 0.3.0 could at most remove a file of the same name in such a directory). Windows: not examined yet, see
  below. The service account (`postgres`) could make root create `90-pg-harden.conf` in a directory of its choice and own the file
  afterwards, for example in `/etc`: by replacing `conf.d` with a link between the check and the write, or by changing `include_dir` in a
  `postgresql.conf` it owns between two reads. A file the service account owns in a directory whose `*.conf` files root evaluates (for
  example `/etc/ld.so.conf.d`) can give it root rights. Reproduced against 0.3.0 in a test container.
  **Check after updating:** `find / -name 90-pg-harden.conf 2>/dev/null` — examine every hit outside the include directory of your
  cluster, and check whether that include directory itself is a link. A hit elsewhere means the host may already be compromised: treat it
  as such (restore or reinstall, change credentials); removing the file alone is not enough.
  The way it works now: root works on a path itself only while every directory on the way belongs to root and nobody else can write it;
  from the first directory of another account on, it works with that account's identity and that account's own groups (no longer root's
  supplementary groups or the group of a directory). It is designed so that a link or renamed directory planted by that account, even
  between check and write, only reaches what the account could reach anyway — test T14 (`tests/lab-identity.php`). The reads for a change
  go the same way (only regular files, size limit). `postgresql.conf` is read once for the change, `apply` creates at most one directory
  level, a directory of root on the way that group or others can write is refused, and the identity of every target is settled before the first
  change. Windows has no identity switch; whether a junction of the service account can redirect a write there has not been examined yet.
- Changed by the security fix: the identity now follows the directories on the way, not the owner of the file. A file of root in a
  directory of the service account is written in place (owner and group stay) if the service account may write it, and refused otherwise —
  the message names the account. `apply` and `rollback` were checked on the Debian package layout (PostgreSQL 17, `/etc/postgresql/17/main`
  owned by `postgres`).
- Fix: `rollback` piped into a command that closes early (for example `| head`) could be killed after restoring the files and before
  finishing: depending on timing before the reload (the server kept running on a configuration that was no longer on disk) or before the
  SQL way back. Output writes now fail quietly instead of ending the process; where `pcntl` is available, `SIGPIPE` is ignored. Regression
  test T12 in `tests/lab-matrix.sh`.
- Fix: a repeated `rollback` after an incomplete one was refused ("Das Journal nennt einen Pfad, den apply auf diesem Server nie schreiben
  würde"), because the first attempt had already removed `conf.d`. Paths below a removed directory are now compared correctly, and entries
  the journal created that are already gone count as done. Regression tests T13 and T13b (interrupted after and before the reload).
- **If a `rollback` of 0.3.0 was interrupted** (no `rollback-log.json` in the journal): run the same `rollback --dir=<journal>` again with
  0.3.1. It restores the same backups again, reloads and runs all rollback statements of the journal again — those that already ran change
  nothing, a `REVOKE` someone else made in between is undone as well. It is complete when it reports "Rückweg abgeschlossen" and `rollback-log.json` exists in the journal. Measured on PostgreSQL 18
  (Debian 13) with a 0.3.0 `rollback` killed by `| head -1`.
- Changed: a `rollback` with files ignores Ctrl+C, Ctrl+\ and `TERM`/`HUP` while it runs (with `pcntl`); on Windows it registers the console
  handler `apply` already uses for Ctrl+C and Ctrl+Break (not tested on Windows). Other signals such as `kill -9` still end it — then run
  the same command again. `apply` also restores its backups on Ctrl+\ now.
- Changed: outside Windows, a `rollback` that restores files requires the PHP extensions `pcntl` and `posix`, like file changes by `apply`
  (Debian's `php-cli` includes both), and refuses to start without them, before changing anything. Without `posix` no journal is accepted.
- Reports (`check`, `verify`, text and HTML) are structured: summary first, findings grouped by severity with rule id and places, then rules
  to review, incomplete, skipped and clean ones. The intended-use and no-warranty notices moved to a closing "Hinweise" block.
- `apply` prints planned changes, the rules that still need an approval (collected in one list) and the result steps in sections; `rollback`
  prints its steps. The confirmation prompt of `apply` goes to stderr, so it stays visible when stdout is redirected.
- [examples/](examples/): unedited output of every command against a throw-away PostgreSQL 18 container, recreated with
  `examples/generate.sh`.

## 0.3.0 (2026-10-24) — first public release

- Commands: `check`, `plan`, `verify`, `client`, `apply`, `rollback`, `rules`; 72 rules (61 for the server, 11 for the client machine).
- Weak-password check without a login attempt (SCRAM-SHA-256 and md5 verifiers recomputed for a fixed candidate list, optional operator list
  with `--extra-candidates`, at most 100 terms).
- Operating-system rules for Linux and Windows (permissions, service account, TLS keys, socket, package origin or signature).
- `client` mode: audits the machine you connect from (password files, environment, scripts, cron, systemd, scheduled tasks, client keys).
- `apply` / `rollback` with a backup journal, validation by the server (`pg_hba_file_rules`, `pg_file_settings`), a new login test after the reload,
  protection against lockouts, `hba` fixes (`trust`/`md5`/`password` → `scram-sha-256`, `host` → `hostssl`), and an allowlist for the SQL it runs
  (exact shapes, the way back must be the exact inverse of the fix).
- New rule `db.public_connect` (`PUBLIC` without `CONNECT`) and `db.catalog_visibility` (database and role names not readable by everybody), with
  measured behaviour, limits and a filtered-view recipe in the README.
- Tested on PostgreSQL 14, 15, 16, 17, 18 and 19rc1 (Docker, Debian 13): [tests/VERSIONSMATRIX.md](tests/VERSIONSMATRIX.md). The catalog revoke
  survives `pg_upgrade` (17 → 18, 14 → 19rc1) and a `pg_dumpall` restore.
- Documentation in English (`README.md`) and German (`README.de.md`). The tool's own output is in German.
