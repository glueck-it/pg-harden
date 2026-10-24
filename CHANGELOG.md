# Changelog

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
