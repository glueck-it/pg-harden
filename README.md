# pg-harden — PostgreSQL security audit and hardening tool

**English** · [Deutsch](README.de.md)

pg-harden checks a PostgreSQL instance against a catalog of security rules, writes a change plan, compares before/after reports,
audits the machine you connect from, and — only on explicit command — applies selected fixes with a backup and a way back.
It covers `postgresql.conf`, `pg_hba.conf`, TLS, SCRAM-SHA-256 password storage, weak passwords, roles and privileges, `PUBLIC` grants,
`SECURITY DEFINER` functions, logging, and the operating-system side (file permissions, service account) of PostgreSQL 14 to 18 and
19 RC1. A PHP command-line tool without Composer dependencies (PHP 8.3 with `pdo_pgsql` and `mbstring`).

- **86 rules** (74 for `check`, 12 for `client`), each with severity, rationale, remediation and — where it is safe — a SQL or
  configuration fix with its rollback
- **Read-only by default:** `check`, `plan`, `verify`, `client` and `rules` are designed not to write to the server. Every database check runs as a single
  prepared statement in `BEGIN TRANSACTION READ ONLY … ROLLBACK`
- **`apply` with a safety net:** dry run first, backup journal, validation by the server itself (`pg_hba_file_rules`, `pg_file_settings`),
  a new login test after the reload, automatic restore on failure, and `rollback` afterwards. It is designed never to restart the server
- **Weak-password check without a single login attempt:** the stored SCRAM-SHA-256 and md5 verifiers are recomputed for a small, fixed list
  of obvious candidates (plus an optional operator list of at most 100 terms; no external wordlists); a report only names the role, never the password
- **Run-tested on PostgreSQL 14, 15, 16, 17, 18 and 19rc1** (Docker, Debian 13) and PostgreSQL 18 on Windows 11 — the matrix shows that the tool
  runs and where versions differ, not how well each rule detects problems; see [tests/VERSIONSMATRIX.md](tests/VERSIONSMATRIX.md) (German)
- Output as terminal text, HTML or JSON; mappings of the rules to BSI IT-Grundschutz `APP.4.3` (identifiers verified against the BSI original) and, preliminary, to ISO/IEC 27001:2022 Annex A and the CIS PostgreSQL Benchmark (identifiers not yet verified; for CIS an own grouping, not CIS identifiers)

pg-harden is not an implementation of a published benchmark and does not replace one, nor a review of your own requirements. It adds a change
plan with rollback, a check of the client machine and an `apply` step.

Maintained by [Frank Glück](https://dozent.net) — database consultant, developer, and trainer. Legal notice / Impressum: <https://dozent.net/informationen/impressum>.

This English README is a condensed version of [README.de.md](README.de.md), which is complete. Notes that only appear there are marked *(see German)*.

## Intended use

> pg-harden is intended for hardening your own systems or systems you have been expressly commissioned to harden. The password check
> reads `pg_authid` only with superuser rights, recomputes a small, fixed list of obvious candidates and optionally an operator-supplied list of at
> most 100 operator-specific terms (no dictionaries, no brute force), produces no failed logins and never outputs a password — only the fact
> that a role uses a value from the check list. The client mode with `--user` reads files and environments of other user accounts and requires
> administrator or root rights **and** the authority to audit those accounts; secrets found are reported with location and line only.
> Reports can contain role-related findings that can be attributed to individuals: treat them as confidential, use them only for remediation, delete them
> promptly; where roles are assigned to employees, observe data protection and works-council co-determination rules. Use on foreign systems or
> accounts without authorization is contrary to the intended use.

*The wording of these two notices ("Intended use" and "Check it yourself — no warranty") is a translation. The original German text is shown by
`--help` and in the separate "Hinweise" block at the end of the reports: the intended-use notice in every report with password or client results,
the no-warranty notice in every report and in the output of `apply` and `rollback`. The tool's own output is in German.*

## Check it yourself — no warranty

pg-harden is an aid, not an approval. It is provided under the MIT License without any warranty (see [LICENSE](LICENSE)).

- Assess findings yourself: not every finding is a defect in every environment, and not every defect has a rule in the catalog.
- A run without findings only means that the rules of the catalog found nothing — not that the instance is secure.
- Plans are proposals. Check every change yourself, try it in a test environment, and only then apply it to production. `apply` does what
  you approve — with backup and rollback, but without a guarantee for your applications.
- The mapping to standards is not a statement that they are met.

A short form of this notice appears in `--help`, at the end of every report and in every plan file.

## Requirements

- PHP 8.3+ with `pdo_pgsql` and `mbstring` (for the certificate check of `client` also `openssl`, on Linux for `--user` and file
  permissions `posix`; outside Windows `apply` and `rollback` need `pcntl` and `posix` to change files); no other dependencies
- Windows: Windows PowerShell 5.1 (ships with the system) for ACLs, service account and scheduled tasks
- Password via `PGPASSWORD` or the pgpass file — never on the command line
- Rights: superuser for the full scope. With fewer rights almost all rules still run; skipped ones are reported as "skipped" and "incomplete":

```sql
CREATE ROLE pgharden LOGIN;                                        -- the prefix pg_ is reserved for system roles
GRANT pg_monitor TO pgharden;                                      -- includes pg_read_all_settings
GRANT EXECUTE ON FUNCTION pg_hba_file_rules() TO pgharden;         -- rules about pg_hba.conf: the function ...
GRANT SELECT ON pg_hba_file_rules TO pgharden;                     -- ... and the view
-- only auth.md5_passwords and auth.weak_passwords need a superuser (pg_authid)
-- after db.catalog_visibility (see below), additionally in every database:
-- GRANT SELECT ON TABLE pg_catalog.pg_database, pg_catalog.pg_roles TO pgharden;
```

Exception: if `SELECT` on `pg_database` is missing (after `db.catalog_visibility`), the run aborts because the database list is missing.

## Quick start

```bash
php pg-harden.php check  --host=db1 --user=postgres                       # report in the terminal
php pg-harden.php check  --host=db1 --user=postgres --format=html --out=report.html
php pg-harden.php plan   --host=db1 --user=postgres --dir=plan-2026-10-23  # new directory, writes files only
php pg-harden.php verify --host=db1 --user=postgres --previous=plan-2026-10-23/report.json
php pg-harden.php client [--user=account] [--scan=/opt/backup,/srv/compose]  # audit this machine, no database connection
php pg-harden.php apply  --host=db1 --user=postgres                        # dry run: shows what would happen
php pg-harden.php apply  --host=db1 --user=postgres --execute --dir=apply-2026-10-24 [--yes]
php pg-harden.php rollback --host=db1 --user=postgres --dir=apply-2026-10-24
php pg-harden.php check  --host=db1 --user=postgres --extra-candidates=company-terms.txt   # + own terms (max. 100)
php pg-harden.php rules
```

**See exactly what it produces:** [examples/](examples/) contains the real output of every command against a sample instance — report
(text and HTML), plan files, dry run, `apply` with its journal, `verify`, `rollback`, `rules`, `client`, and the lockout protection refusing a
`pg_hba.conf` change.

Connection: `--host`, `--port`, `--user`, `--dbname` (entry database, default `postgres`), `--sslmode`, `--databases=a,b`. As in psql,
`-h`, `-p`, `-U`, `-d` and `--username` work as well — long forms `--host=db1` or `--host db1`, short forms `-h db1` or `-hdb1` (no `=`):
`php pg-harden.php check -h db1 -U postgres`. `-U` and `--username` always mean the database user; for `client`, `--user` names an account
of the machine. Help: `--help` or `-?` (`-h` is the host, as in psql). Without `--host`/`--port` the libpq defaults apply (`PGHOST`,
`PGPORT`, socket). For remote hosts `sslmode=require` is the default; `verify-full` is preferable.
Behind PgBouncer in transaction pooling session settings are not reliable — connect directly.

Exit codes: `0` no findings · `1` findings · `3` no findings, but not everything was checked (missing rights, errors, skipped or locked
databases; for `verify` also a different server, user or scope) · `2` abort (also unknown options; for `apply`/`rollback` a failed run).

## The plan

The plan is an **automatically generated proposal**. Check the effect on your applications in a test environment before applying it.

| File | Content |
|---|---|
| `90-pg-harden.conf` | Parameters for `include_dir 'conf.d'` (at the end of `postgresql.conf`). Warns if a value comes from the command line, `postgresql.auto.conf` or `ALTER DATABASE/ROLE … SET` and the file therefore has no effect |
| `harden_<db>.sql` | SQL fixes per database in one transaction, each with its way back as a comment. The first statement aborts if the file runs in another database. Connect to the target database itself and run it with `psql -v ON_ERROR_STOP=1 -f <file>` |
| `MANUELL.md` ("manual items") | Findings without an automatic fix (also `pg_hba.conf` changes that only `apply` performs), objects that cannot be planned, rules not checked completely |
| `report.json` | Baseline report for `verify` |

Levels per rule: `auto` (low operational risk, active in the plan), `confirm` (commented out, enable deliberately), `manual` (only in
`MANUELL.md`). Objects with control or format characters in their name (including bidi characters) and fix SQL with characters psql would
interpret are never written to an SQL file. The plan directory must be new or empty and owned by the calling user; files are created
exclusively, and nothing half-finished is left behind on abort.

`verify` counts an earlier finding as fixed only if exactly that place — for database findings exactly that database — was checked again in the
current run; otherwise it is reported as "not comparable".

## `apply` — run the plan, protected against lockouts

`apply` is the only command that changes the server. Without `--execute` it only shows what it would do.

- **Selection:** rules of level `auto` run. Rules of level `confirm` need their id in `--include-confirm=ID,ID` — there is no blanket approval.
  `--rules=ID,ID` restricts the run.
- **Connection:** writing (`apply --execute`, `rollback`) over a remote connection requires `--sslmode=verify-full`; without that check `apply`
  aborts. The same applies to the password check in `check`, which reads the verifiers.
- **Configuration files** (`postgresql.conf`, `pg_hba.conf`) can only be changed if `apply` runs **on the server itself** (proof: this
  machine's `postmaster.pid` belongs to the connected instance) and has write rights. Otherwise these actions are skipped with a reason; SQL
  fixes also run remotely.
- **Parameters** go to `conf.d/90-pg-harden.conf`; if no active `include_dir` exists, `apply` adds it at the end of `postgresql.conf` (with a
  backup). Values that would be overridden from the server command line or `postgresql.auto.conf` are not written. Parameters needing a
  restart are written and reported — **`apply` never restarts the server.**
- **`pg_hba.conf`:** only one field changes (method `trust`/`md5`/`password` → `scram-sha-256`, `host` → `hostssl`); comments and spacing stay.
  `apply` never touches `local` lines. Preconditions against lockout: all roles that can log in have a SCRAM password (for `trust` at least
  a password), and for `hostssl` `ssl` is on.
- **Sequence:** backup into the journal → write in place → the server validates the files on disk (`pg_hba_file_rules`, `pg_file_settings`;
  any deviation or error restores **without** reloading) → `pg_reload_conf()` → a **new** login with the same credentials (existing sessions
  survive a broken `pg_hba.conf` and prove nothing) → on failure restore the backups, reload again, check again.
- **File access as root:** root works on a path itself only while every directory on the way belongs to root and nobody else can write it.
  From the first directory of another account on (usually the service account), `apply` and `rollback` work with that account's identity and
  its own groups. This is designed so that a link or renamed directory planted by that account, even between check and write, reaches
  nothing beyond its rights (test T14). Reads for a change go the same way (only regular files, size limit). A directory of root on the way
  that group or others can write is refused; the identity of every target is settled before the first change. `postgresql.conf` is read once for
  the change; `apply` creates at most one directory level. A file of root in a directory of the service account is written in place if that
  account may write it, otherwise refused. Windows has no identity switch: there a helper (`WindowsPin`) holds the root and target directories
  open without `FILE_SHARE_DELETE` (an empty one also without `FILE_SHARE_WRITE`) for the entire file phase of `apply` and `rollback` and checks on these handles, before
  and after every write, that each directory is still a plain directory under its final path (`GetFinalPathNameByHandleW`): no directory can be
  renamed away and replaced by a junction between check and write, and one changed in place stops the operation; without a running helper
  nothing is written; ACLs and `postmaster.pid`
  are read via the open handle or the same redirect check (`client --user` and `check` refuse paths through junctions or symbolic links;
  remaining limits in the CHANGELOG). Files are replaced via a
  temp file (Windows: write first, then truncate), never emptied beforehand. If the process dies in the middle of the file phase, a watchdog
  restores the backups — outside Windows only with the PHP extensions `pcntl` and `posix`; without them `apply` does not change files.
- **Reload:** an unconfirmed reload counts as an error.
- **`local` lines** of `pg_hba.conf` are never touched, so access through the Unix socket stays. A reload that is not confirmed counts as an error,
  because the login test would otherwise still see the old configuration. *(more detail: see German)*
- **Limits of the login test:** it checks this tool's login with the same credentials — not applications, other roles or clients without TLS.
  Before `host` → `hostssl`, `apply` refuses if connections from other machines without TLS currently exist.
- **SQL:** per database in one transaction with `lock_timeout`; only single, simple `GRANT`, `REVOKE` and `ALTER ROUTINE` statements of the exact
  shapes the rule catalog produces (a list of `pg_catalog` objects for catalog visibility, never an application table), and only with a way back.
  The way back must be the exact inverse of the fix. The server itself refuses multiple statements (`prepare`). The way back is in the journal
  **before** the commit.
- **Journal** (`--dir`, new directory): `apply-log.json`, `backup/`, `report-before.json`, `report-after.json`. After the run `apply` checks
  again with **new** connections and shows fixed/new/open.
- **`rollback --dir=<journal>`** restores the backups, reloads, tests a new login and runs the stored rollback statements. The journal is accepted
  only if it belongs to the executing user and is inaccessible to others, belongs to the same cluster (system identifier, data directory) and
  names only paths `apply` would write on this server. A journal can be rolled back only once. Later changes by third parties to the same files are
  overwritten. An incomplete rollback (error or interruption) writes no `rollback-log.json` and can be repeated with the same command; it then
  restores the same backups again and runs all rollback statements of the journal again (those that already ran change nothing; a `REVOKE` made
  by someone else in between is undone as well). It is complete when it reports "Rückweg abgeschlossen" and `rollback-log.json` exists. While a
  rollback with files runs, Ctrl+C, Ctrl+\, `TERM` and `HUP` do not interrupt it (where `pcntl` is available); other signals such as `kill -9`
  still end it — then run the same command again. Outside Windows a rollback with files needs the PHP extensions `pcntl` and `posix`.
- Without a terminal `--execute` additionally requires `--yes`; a second simultaneous `apply` on the same server is refused.

## Weak passwords (`auth.weak_passwords`)

The stored SCRAM-SHA-256 and md5 values from `pg_authid` are recomputed for a small list fixed in the program (role name with variants and
years, `postgres`, `password`, `admin` and the like). No login attempts, no load on the server, no external wordlists or dictionaries. Only the role is output — never
the password, not even which candidate matched. Superuser required.

**Own terms:** `--extra-candidates=FILE` extends the fixed list with terms of the operation (company name, products, place, house standard).
Deliberately limited so it stays a check list and does not become a dictionary: at most 100 entries (one per line), at most 64 characters each,
ASCII only; more aborts the run. The terms are checked exactly as written (no automatic variants). The file must belong to the executing user and
be inaccessible to others (Unix: `chmod 600`). It is never passed on the command line or stdin. The report only says *how many* terms were checked.
Lines with leading or trailing spaces are rejected. Use operation-specific terms only, no personal data of third parties, and delete the file after
the run. An example is in `lab/extra-candidates.example.txt`.

## Catalog visibility (`db.catalog_visibility`)

By default every role that can log in can read all database and role names (`\l`, `\du`, GUI tools) — also those of databases it may not connect
to. Revoking `CONNECT` (`db.public_connect`) blocks access but does not hide the names. The rule `db.catalog_visibility` (level `confirm`) revokes
the read right of `PUBLIC` on `pg_database`, `pg_roles`, `pg_user`, `pg_group`, `pg_auth_members`, `pg_stat_database`,
`pg_stat_database_conflicts` and `pg_shdescription`. The fix is a single `REVOKE` per database with `GRANT` as the way back; run it with
`apply --include-confirm=db.catalog_visibility`.

Measured in PostgreSQL 14 to 19rc1 (`tests/lab-visibility.sh`, same result in all versions):

- **The privilege belongs to each database individually.** `pg_database` is a shared catalog, but its privilege is stored in each database's
  `pg_class`; a `REVOKE` acts only in the database it runs in. The rule therefore checks every database and `template1` (new databases inherit
  from there). `template0` is not checked: a database created with `TEMPLATE template0` does not carry the revoke, but shows up as a finding at
  the next `check`.
- **What fails afterwards** (for all roles without their own `SELECT`): `\l`, `\du`, tree views and pick lists of GUI tools, `pg_dump` as a
  non-superuser (needs `pg_database` and `pg_roles`) and everything else that reads these catalogs. `\d`, `\dt`, `\dn`, `\df` and `\dp` kept working
  in the test. Applications that read these catalogs — monitoring (e.g. an exporter on `pg_stat_database`), drivers with metadata queries,
  administration tools — need a targeted `SELECT` first; that depends on the application and cannot be predicted here: try it in a test
  environment. Superusers are not affected.
- **The revoke is in the dump and survived the tests.** `pg_dump` carries it as `REVOKE … ON TABLE pg_catalog.…`. Measured (`tests/lab-upgrade.sh`):
  after `pg_upgrade` from 17 to 18 and from 14 to 19rc1, and after restoring a `pg_dumpall`, `PUBLIC` has no read right in `template1` and in all
  databases; a new database from `template1` inherits the revoke. Run `check` after every upgrade or restore anyway.
- **Rollback:** `rollback` gives `PUBLIC` the read right back — also on objects for which someone has deliberately revoked it in the meantime.
  It covers only the databases that were checked at fix time; databases created from `template1` afterwards inherit the revoke and need the
  `GRANT` themselves.
- **Limits — this is not secrecy.** Role names can still be found through their id (`SELECT g::oid::regrole FROM generate_series(1, 70000) g`),
  and the error message on a connection attempt distinguishes `permission denied for database` from `database … does not exist`. The list of eight
  objects is not exhaustive: `pg_stat_activity` still shows database and role names of running sessions; replication views and tablespaces were not
  examined. There is no real row filtering in the catalog: PostgreSQL rejects row-level security on system catalogs (measured in 18). Anyone who
  must really separate tenants runs **separate clusters** per tenant.

**Filtered view for users** (manual, as superuser in every database where it is needed — pg-harden creates no objects; the owner needs `SELECT`
on `pg_database`). The view runs with its owner's rights, but `has_database_privilege` evaluates the calling user. **`security_barrier` is
required:** without it, a function a user put into `WHERE` could run before the view's filter and see the names of all databases in the test
(PostgreSQL 18); with `security_barrier` it saw only the permitted ones.

```sql
CREATE SCHEMA visibility;
GRANT USAGE ON SCHEMA visibility TO PUBLIC;
CREATE VIEW visibility.databases WITH (security_barrier = true) AS
SELECT d.datname
  FROM pg_catalog.pg_database d
 WHERE NOT d.datistemplate
   AND pg_catalog.has_database_privilege(d.datname, 'CONNECT');
GRANT SELECT ON visibility.databases TO PUBLIC;
```

## Operating-system rules (category "Betriebssystem", `check`)

Only when pg-harden runs on the server. The report header says whether the rules were checked or why not (remote server or container;
`postmaster.pid` unreadable). Checked: permissions of the data directory, custom tablespaces, configuration (including files pulled in via
`include`/`include_dir`) and log files, TLS keys, expiry of server and CA certificates and socket (Linux: modes; Windows: ACL via the open handle
against Everyone/Users/Authenticated Users), service account, service file or Windows service registry (including unquoted `ImagePath` and service
key ACL) and process environment for plaintext secrets (location and name only), umask, log directory on its own volume, free space, package
origin (Linux) or signature (Windows).

## `client` — the machine you connect from

No database connection (`verify --previous=<client-report.json>` also compares earlier client reports). For the current account or (with `--user`, administrator/root required) another account: `pg_service.conf` with
`password=`, the password file (Windows ACL, location in cloud folders, on network shares or in roaming profiles, superuser entries with wildcard
host, hidden lines, missing loopback entries; on Unix only a hint, because libpq ignores the file when its permissions are open anyway),
`psql` command history (`psql_history` / `.psql_history` permissions and plaintext passwords), `PGPASSWORD` in environment and registry, passwords in profiles, scripts, compose and `.env` files, cron, systemd files and the Windows task
scheduler, client keys and certificates (permissions, expiry). Secrets found are reported with location and line only.

`--user` searches the whole profile of the other account, not just PostgreSQL files. For employee accounts that needs a legal basis (in
Germany, where applicable, § 26 BDSG — the Federal Data Protection Act — or Art. 6(1)(f) GDPR) and possibly a works agreement; reports carry account name, machine name and paths. In addition to the profile, `client`
reads system-wide places (`/etc/environment`, `/etc/profile.d`, `/etc/cron.d`, `/etc/systemd/system`, `/usr/local/bin`) — also with `--user`.

The profile search is bounded (depth 4, 20,000 entries, 25 s; dot folders, cloud folders and pure data folders are skipped — files in cloud
folders would be downloaded when read). More directories with `--scan=a,b`.

## Reports contain role, object and network names

Role names are often personal identifiers, `pg_hba` lines contain networks. Reports (`--out`), plan and journal directories are written with file
permissions for the executing account only (on Windows plus `SYSTEM` and `Administrators` via `icacls`). Store confidentially, check before passing
to third parties, define a retention period.

## Rules and mappings

- `rules/*.json` — rules as data: check by parameter (`setting`), SQL (`query`, one row per finding) or built-in check (`weak_passwords`, `os`,
  `client`), version, required rights (`requires`), platform, command (`check`/`client`), fix (`conf`, `sql`, `hba`, `manual`) and way back, rationale
- `mappings/*.json` — mapping to BSI IT-Grundschutz `APP.4.3 Relationale Datenbanken` (Edition 2023, identifiers and titles verified against the official BSI PDF)
  and preliminary mappings to ISO/IEC 27001:2022 Annex A and the CIS PostgreSQL Benchmark (own grouping along sections 1–7, not CIS
  identifiers; the identifiers of ISO and CIS are not yet verified). Identifiers and own short titles only,
  no standard or benchmark text; a mapping says which rules relate to a requirement, not that it is fulfilled. CIS Benchmarks is a trademark of
  the Center for Internet Security; pg-harden is not affiliated with, endorsed or certified by CIS

The tool delivers technical results that can serve as evidence in an audit. The mapping only shows the result of the rules assigned to each item —
it is not a statement that a requirement of the standard is met; organizational parts are not checked.

## Test instance and tests

`lab/` starts a PostgreSQL 18 with deliberately weak configuration and attack cases for the tool itself (bound to 127.0.0.1 only; Docker 28 or
newer). The roles `weak_*` and `analyst` deliberately have obvious passwords for the password check:

```bash
docker compose -f lab/docker-compose.yml up -d
php pg-harden.php check --host=127.0.0.1 --port=55432 --user=postgres
docker compose -f lab/docker-compose.yml down -v
```

Operating-system rules, `apply` and `rollback` need access to the server's files. To practise them, install PHP in the container, copy the directory
in and run as root there. Practise against `lab/` only — never against production systems.

`tests/` contains `allowlist-test.php` (unit test of the allowlist that `apply` and `rollback` pass SQL through: `php tests/allowlist-test.php`),
`catalog-test.php` (offline test of the rule catalog, framework mappings and `Verifier`), `options-test.php` (offline test of the command
line, long names and psql-style short options), `windows-redirect.php` and `windows-admin-test.ps1`
(Windows path verification, handle ACLs and directory pinning `WindowsPin` against junctions; the second one runs with a temporary local account
without administrator rights in an elevated PowerShell),
`lab-matrix.sh` (regression run of `apply`/`rollback` in a container, calls `lab-identity.php` for the identity rules when writing and reading as root),
`lab-visibility.sh` and `lab-upgrade.sh` (catalog visibility, `pg_upgrade`,
restore) and `run-version-matrix.sh` with `matrix-table.php` (version matrix, result in [tests/VERSIONSMATRIX.md](tests/VERSIONSMATRIX.md)). The
container scripts change passwords, roles and databases and only start with `PGHARDEN_LAB=1` — **run them only in a throw-away container**, never
against an instance with real data.

## Status

0.4.0 (unreleased): Windows write side holds the server's directories against a swap for a junction via open directory handles without `FILE_SHARE_DELETE` (`WindowsPin`),
handle-based ACL reading (`GetSecurityInfo`/`GetFinalPathNameByHandleW`), restricted ACLs for journals and output files on Windows (checked when a journal is loaded), `verify`
support for client reports, rule catalog expanded to 86 rules (74 for `check`, 12 for `client`), mappings for BSI IT-Grundschutz `APP.4.3`
(identifiers verified against the BSI original) and, preliminary, the CIS PostgreSQL Benchmark added. Details in [CHANGELOG.md](CHANGELOG.md).

0.3.2 (2026-10-26): **security fix** for `check` and `client` as root (another account could make them read a file of root through a
link, steer the process probes to a foreign process via `postmaster.pid`, or stop `check` with a FIFO); files of other accounts are now
read with that account's identity. Details in [CHANGELOG.md](CHANGELOG.md).

0.3.1 (2026-10-25): **security fix** for `apply`/`rollback` as root (the service account could redirect a write into a directory of root and
gain root rights that way; after updating, check as described in [CHANGELOG.md](CHANGELOG.md)), fix for `rollback` in a
pipe that closes early (for example `| head`), a repeatable rollback after an interruption, structured reports, [examples/](examples/).
Details in [CHANGELOG.md](CHANGELOG.md).

0.3.0 (2026-10-24): `check`, `plan`, `verify`, `client`, `apply`, `rollback`, `rules`; 72 rules (61 for `check`, 11 for `client`). New compared to
0.2.0: password check without login attempts, operating-system rules for Linux and Windows, `client`, `apply`/`rollback` with lockout protection,
`hba` fixes, rule `db.catalog_visibility`. Tested with PostgreSQL 14 to 18 and 19rc1 ([tests/VERSIONSMATRIX.md](tests/VERSIONSMATRIX.md)); PostgreSQL 19
is still a release candidate. Planned: permissions target/actual against a target file, manual confirmations and an evidence package with hashes,
pseudonymization of reports, BSI identifiers, OSCAL, English output texts. See [CHANGELOG.md](CHANGELOG.md).

## Related projects and training

- **[pg-harden product page](https://dozent.net/produkte/pg-harden)** (German) — overview with sample output.
- **[pg-clusterbackup](https://github.com/glueck-it/pg-clusterbackup)** — backs up every database of every running PostgreSQL cluster in one
  scheduled job (PHP, Bash, PowerShell).
- **[PostgreSQL Konfigurator](https://dozent.net/produkte/postgresql-konfigurator)** — a web-based tool to generate optimized, hardware-tailored
  `postgresql.conf` configurations.
- **[Seminar: PostgreSQL security and hardening](https://dozent.net/seminare/postgresql/postgresql-security-haertung)** (training, in German) — the
  background to the rules in this tool.

## License

MIT License, Copyright (c) 2026 Frank Glück (Glück IT) — see [LICENSE](LICENSE). It covers code, rule catalog and mappings; they contain original
texts, the identifiers of the standards and original short titles in the spirit of them, but no standard or CIS texts. Mandatory statutory
liability (in particular for intent, fraud, injury to life, body and health, and under the Product Liability Act) remains unaffected.

## About the author

Built and maintained by **Frank Glück** ([Glück IT](https://dozent.net)) — a consultant, developer, and trainer working with databases and
programming languages. A lot of my current project work is migrating databases to PostgreSQL from
[Oracle](https://dozent.net/seminare/postgresql/migration/migration-von-oracle-zu-postgresql),
[SQL Server](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-sql-server),
[DB2](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-db2),
[Informix](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-informix),
[Sybase](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-sybase), or
[MS Access](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-ms-access).

- Need help with PostgreSQL itself, a security review, a migration, or backup strategy? [Get in touch](https://dozent.net).
- I also run seminars (German) on [PostgreSQL administration](https://dozent.net/seminare/postgresql/postgresql-administration),
  [performance tuning](https://dozent.net/seminare/postgresql/postgresql-performance-tuning),
  [PL/pgSQL](https://dozent.net/seminare/postgresql/plpgsql-programmierung), SQL Server (T-SQL/SSRS/SSAS),
  [PHP](https://dozent.net/seminare/programmieren/php), JS, and other web technologies.
- I'm also building [Inside Filings](https://inside-filings.com/news) — tracking notable insider, congressional/White House, and 13F fund moves
  from SEC filings and other official disclosures.
