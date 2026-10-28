# Changelog

## Unreleased

- **Command line as in psql, in addition to the long names:** `-h HOST`, `-p PORT`, `-U USER`, `-d DBNAME` and `--username`. Long
  forms take the value after `=` or as the next argument (`--host=db1`, `--host db1`; also every other option with a value, such as
  `--out report.html`), short forms as the next argument or attached (`-h db1`, `-hdb1`); a value starting with `=` (`-h=db1`,
  `--host==db1`) is refused. `-h` is the host as in psql; help is `--help` or `-?` and wins wherever it stands. A value given as the next argument never starts with `-`, so a
  forgotten value fails instead of swallowing the next option; options without a command are refused (exit code 2) instead of printing
  the help with exit code 0. `-U` and `--username` always mean the database user and are refused for `client`, where `--user` names an
  account of the machine. An option given twice (also as long and short form) is refused. Test: `tests/options-test.php` (offline,
  34 cases).
- **Windows, `apply`, `rollback`, `check` and `client --user=<account>`: the write side holds the server's directories against a swap for a junction, handle-based ACL
  reading, and redirect checks below the profile and the server's data directory.** Windows has no identity switch (`Fs::asOwnerOf` /
  `Fs::asReaderOf` cannot drop administrator privileges to the service or user account), so a non-administrator who owns or may write the
  data directory or profile can place junctions there.
  - **`apply` and `rollback` on Windows (`WindowsPin`, `ServerFiles::overwrite`, `create`, `makeDir`, `restore`, `Journal::backup`):**
    a persistent PowerShell 5.1 helper (`WinHandle`, Win32 `CreateFileW` with `FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES`,
    `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, without `FILE_SHARE_DELETE`) holds the server's root directories
    (`data_directory` and the directory of `postgresql.conf`) and every target directory on the way open for the duration of the file
    phase, from before the first read of `postgresql.conf`. Each handle is verified not to be a reparse point
    (`GetFileInformationByHandle`) and its final path (`GetFinalPathNameByHandleW`) must match the expected path from the root down.
    While held this way, Windows refuses to rename or delete any pinned directory, so no directory on the way can be renamed away and
    replaced by a junction between check and write. An empty directory (such as a new `conf.d`) is held without `FILE_SHARE_WRITE` as
    well, because only an empty directory can be turned into a junction in place (by design; that conversion itself is not reproduced in
    the tests, and a directory with content could be emptied first — the handle check below catches such a change); a directory with content keeps `FILE_SHARE_WRITE`, so the server can
    still rename files in its data directory (`ALTER SYSTEM`, `current_logfiles`) during the file phase. Before and after each file
    operation `WindowsPin::verifyTarget` has the helper check on all held handles that every directory is still a plain directory under
    its final path, and checks the target entry; a change aborts the operation (and the run restores its backups). Newly created
    directories (`conf.d`) are added to the active hold without releasing parent handles; `restore` releases only the removed
    directory's handle right before `rmdir`. Fail-closed: without an active hold, with a helper that cannot start, has ended or does not
    answer (30 s, then terminated), or with a path that redirects, nothing is written. Every restore (failed run, `Guard` after Ctrl+C,
    `rollback`) rebuilds the hold over the server's directories first; the helper runs in its own process group, so Ctrl+C reaches
    only PHP. Answers of the helper carry the id of their request. `apply` writes only below the data directory and the directory of
    `postgresql.conf` (unchanged), so a journal never names other targets.
  - **ACL reading via the open handle (`GetSecurityInfo` + `GetFinalPathNameByHandleW`):** replaces `Get-Acl -LiteralPath` in
    `WindowsFacts::get`/`aces`, `WindowsFacts::strictAcl`, `WindowsFacts::broadAcesOf` (`src/Os.php`) and `ClientProbes::windowsFacts` /
    `aclProblems` (`src/Client.php`). Each path is opened once; both its final path and its security descriptor are read from that
    handle, and the ACL is used only if the handle's final path is not redirected (`Fs::windowsRedirected`).
  - **`check` on Windows (`LocalServer::detect`):** reads `postmaster.pid` in the data directory with `Fs::readGuarded(..., $dir)` using
    the data directory as base, refusing junctions inside the data directory.
  - **`client --user=<account>` on Windows:** a file below the profile is read only if the final path Windows reports for the opened file
    is exactly the profile plus the remaining names, checked before and after reading (`Fs::readGuarded`, `Fs::windowsRedirected`).
    Reported as "nicht geprüft" instead: a way through a junction or symbolic link, a path that cannot be resolved, one with `..`, and
    one that reaches into the profile under another spelling (a short name such as `FRANK~1`; forward slashes, case and a leading
    `\\?\` are compared as mere spelling).
  - **Remaining limits on Windows:** on the read side (`check`, `client --user`), content reads check the path before and after reading
    and verify `stat`/`fstat` identity rather than holding parent directories open without `FILE_SHARE_DELETE`. A hard link is no
    redirect by its path; Windows 11 lets a non-administrator create one only to a file the account may write. Whether a file exists, its
    name and its size may still be taken through a redirect. Files outside the profile or data directory are not judged.
  - **Strict ACLs for journals, plan directories and `--out` reports on Windows (`Files::lockDown`, `Journal::load`,
    `WindowsFacts::isStrictlyPrivate`):** `Files::prepareDir` and `App::output` (`--out`) restrict the directory or file to the
    executing account, `SYSTEM` and `Administrators` (`icacls`) — changed: also an existing empty directory given with `--dir` (on Linux
    and other Unix systems `chmod 0700` on it as well), which on Windows must belong to this account, `SYSTEM` or the Administrators (an
    owner keeps the right to change the ACL); a directory of another account is refused before its ACL is touched. A `--out` report is
    written to a new file of this account, restricted while still empty, and then renamed into place (on every platform), so a handle
    kept open on an existing file of that name never sees the new content. Without the own SID (`whoami`) nothing is restricted and the
    run stops. `Journal::load` verifies via the open handle that owner and entries leave no other SID access before trusting a journal.
  - **`check` without full rights (all platforms):** when `pg_file_settings`, `pg_hba_file_rules` or `pg_tablespace` cannot be read,
    `os.config_permissions` and `os.tablespace_permissions` now report "nicht geprüft" instead of passing in silence.
  - **`verify` for client reports and version `0.4.0+`:** `verify --previous=<report.json>` now compares both `check` and `client`
    reports, and `Verifier::isReport` accepts reports from `0.4.0` and later releases.
  - **Tests:** `tests/windows-redirect.php` (throw-away directories in `%TEMP%`, no administrator rights needed), `tests/catalog-test.php`
    (offline test for the rule catalog, framework mappings and `Verifier`) and `tests/windows-admin-test.ps1` (for an elevated PowerShell:
    creates a temporary local non-administrator account, tests `client --user`, `check` and `apply`/`rollback` directory pinning against
    junctions in its profile and data directory, and removes the account and its `ProfileList` entry afterwards; the account never
    logs on, so Windows creates no profile of its own; ran on Windows 11 on 2026-10-28, 19 of 19 cases green).
- **Expanded hardening catalog (86 rules), OS/client probes, BSI IT-Grundschutz APP.4.3 and CIS PostgreSQL Benchmark mappings:**
  - **PostgreSQL server rules (`rules/postgresql.json`):** added `tls.ciphers`, `hba.weak_options` (`ident` over TCP and
    `clientcert=verify-ca`), `auth.passwordless_or_expired`, `roles.replication_login`, `roles.createrole_self_grant` (PostgreSQL 16+),
    `db.default_acl_public` (`CREATE` on non-system schemas and `ALTER DEFAULT PRIVILEGES` for `PUBLIC`), `db.rls_policies_inactive`
    (tables with policies in `pg_policy` where `ENABLE ROW LEVEL SECURITY` is off, and tables with `ENABLE ROW LEVEL SECURITY` but no
    policy in `pg_policy`),
    `code.fdw_secrets` (`USER MAPPING FOR PUBLIC` and cleartext secrets in `pg_user_mapping` / `pg_subscription`),
    `code.event_triggers` (inventory), `log.lock_waits` and `data.crash_safety` (`fsync`, `full_page_writes`, `ignore_checksum_failure`,
    `zero_damaged_pages`); extended `conf.role_db_overrides`, `roles.server_file_access` (`pg_read_all_data`, `pg_write_all_data`) and
    `log.pgaudit` (checks that `pgaudit.log` or `pgaudit.log_role` is configured when loaded).
  - **Operating system rules and probes (`rules/system.json`, `src/Os.php`):** added `os.ssl_cert_expiry` (`ssl_cert_file` and
    `ssl_ca_file`), `os.tablespace_permissions` (custom tablespaces from `pg_tablespace`), included files from `pg_file_settings` and
    `pg_hba_file_rules` in `os.config_permissions`, and extended `os.service_unit` to Windows services (unquoted `ImagePath` with spaces,
    secrets in the service's `Environment` registry value, and broad write ACEs on the service registry key).
  - **Client rules and probes (`rules/client.json`, `src/Client.php`):** added `client.psql_history` (checks permissions/ACLs and scans
    `psql_history` / `.psql_history` for `CREATE/ALTER ROLE … PASSWORD`, connection URIs with passwords and `PGPASSWORD`, without
    printing values).
  - **Framework mappings (`mappings/bsi-app43.json`, `mappings/iso27001-2022.json`, `mappings/cis-postgresql.json`):** a mapping
    for BSI IT-Grundschutz-Kompendium (Edition 2023) Baustein `APP.4.3 Relationale Datenbanken` (identifiers, titles and dropped
    requirements verified against the official BSI PDF: `APP.4.3.A1` to `APP.4.3.A25` with 17 active requirements — `A2`, `A5`, `A6`,
    `A7`, `A8`, `A10`, `A14` and `A15` are dropped in Edition 2023; it assigns at least one rule to each active requirement — an
    assignment, not fulfilment; several requirements
    are organisational and cannot be checked by a tool), a new `mappings/cis-postgresql.json` (an own grouping along sections 1–7 of the
    CIS PostgreSQL Benchmark with own short titles — the numbers are not CIS identifiers), and every rule assigned in all three.
    Identifiers of ISO 27001 and CIS are not yet verified against the originals (`"verified": false`, reports say so). CIS Benchmarks is a
    trademark of the Center for Internet Security; pg-harden is not affiliated with, endorsed or certified by CIS.
  - **Corrections from review:** `hba.weak_options` reports only the checked option (never other options of the line such as
    `ldapbindpasswd`/`radiussecret`) and no longer counts `ident` on loopback addresses as network access; `roles.replication_login` only
    roles that can log in; `tls.ciphers` also single weak suites (`RC4-SHA`, `DES-CBC3-SHA` …); `log.pgaudit` also accepts `pgaudit.log` /
    `pgaudit.log_role` set per role or database; `code.event_triggers` names the function with schema and arguments.

## 0.3.2 (2026-10-26)

- **Security fix — update if you run `check` or `client` as root.** Affected: 0.3.0 and 0.3.1 on Linux and other Unix systems;
  reproduced against 0.3.1 in a test container. Both commands change no configuration on the host; the only thing they write is the
  report (`--out`). Reports written as root may contain such findings (places, kinds of finding, variable names; no values) — review or
  regenerate them with 0.3.2. Both commands read files that another account controls, and they read them as root:
  - `client --user=<account>`: the account could link its `.pgpass` (or a service file, certificate or script) to a file only root may
    read — the report then showed findings from root's file as the account's own (places and kinds of finding; values are not printed).
  - `check`: the service account could write any process number into `postmaster.pid`; the process probes then read the environment
    (names of variables containing `PASSWORD`), the owner and the program file of that other process as root and reported them as the
    server's. A FIFO in place of `postmaster.pid` made `check` hang without end.

  The way it works now: such files are read with the identity of the account that controls the way to them (the same walk from `/` as
  for writing). A directory of root that group or others can write — for example `/tmp` — is not refused for reading: with the sticky
  bit an existing entry decides by its owner (a file or link of root there is read as `nobody`, since anybody may have placed a hard link
  to it), otherwise the file is read as `nobody`. Every read opens only a regular file, without blocking and within a size limit. The
  process number counts only when it is the parent of the tool's own database connection; on Linux both processes must also run as the
  owner of the data directory and the start time must match the server's (`/proc`), on Windows the parent is checked in the process
  list. Otherwise the process probes report "nicht geprüft". Windows has no identity switch: whether a junction on the way can redirect a
  read of `client --user` or a write of `apply` there is examined next. Tests: `tests/lab-identity.php` (T14) and T15 in
  `tests/lab-matrix.sh` (forged process number, FIFO); version matrix PostgreSQL 14 to 19rc1, Windows 11 with PostgreSQL 18.

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
