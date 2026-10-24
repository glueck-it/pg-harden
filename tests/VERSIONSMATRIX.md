# Versionsmatrix PostgreSQL 14 bis 19 (Stand 24.10.2026, Programmstand 0.3.0)

Getestet mit `tests/run-version-matrix.sh`: je Version ein Container (`postgres:14-trixie` … `postgres:18-trixie`, `postgres:19rc1`,
Debian 13, PHP 8.4.27, als root im Container, Datenverzeichnis lokal, Vertrauensanmeldung wie in `lab/`). Die Versionen meldete der
Server selbst (`show server_version`): 14.24, 15.19, 16.15, 17.11, 18.6 und 19rc1 — jeweils der Stand der Image-Tags am 24.10.2026.
PostgreSQL 19 ist ein Release Candidate; die Veröffentlichung ist laut der Ankündigung von RC 1 auf postgresql.org (Stand 24.10.2026)
für den 19.11.2026 geplant. Die Spalte 19rc1 ist eine Vorabprüfung, kein Freigabevermerk.

Die Matrix zeigt **Lauffähigkeit und Versionsunterschiede, keine Wirksamkeit der Regeln**: `pass` heißt „kein Befund in dieser frischen
Container-Konfiguration“, nicht „die Regel erkennt Fehler zuverlässig“.

## Ergebnis

- **Kein Fehlerstatus** in `check` auf keiner Version; die Fehlerausgabe ist überall leer.
- **Regressionsläufe** (`tests/lab-matrix.sh`, T1–T11: `apply`/`rollback` von Konfiguration, `pg_hba.conf` mit Aussperrschutz, SQL,
  manipuliertes Journal, entfernte Verbindung, Katalog-Sichtbarkeit) und **Sichtbarkeitsprobe** (`tests/lab-visibility.sh`) liefern auf
  allen sechs Versionen dasselbe Ergebnis — bis auf eine Abweichung in T7: in 14 braucht `db.public_schema_create` eine zusätzliche
  Anweisung (siehe die Tabelle unten, Zeile `db.public_schema_create`).
- **`pg_upgrade` und Wiederherstellung** (`tests/lab-upgrade.sh`, nicht Teil der Matrix, einzeln gelaufen): Der Entzug aus
  `db.catalog_visibility` blieb bei `pg_upgrade` von 17 auf 18 und von 14 auf 19rc1 sowie bei der Wiederherstellung eines `pg_dumpall`
  erhalten (in `template1` und allen Datenbanken).
- Unterschiede zwischen den Versionen sind Versionsunterschiede von PostgreSQL oder der Stand des Support-Katalogs von pg-harden:

| Regel | Unterschied | Grund |
|---|---|---|
| `data.checksums` | Befund in 14–17, ok ab 18 | Prüfsummen sind erst ab 18 Standard bei neuen Clustern |
| `db.public_schema_create` | Befund nur in 14 | `public` ohne `CREATE` für alle ist erst ab 15 Standard |
| `roles.allow_alter_system` | übersprungen in 14–16 | Parameter gibt es ab 17 (`min_version`) |
| `patch.supported_major` | Befund in 14 | Support endet am 12.11.2026 (Fenster von 90 Tagen) |
| `patch.catalog_current` | Befund in 19rc1 | Katalog-Stand: die Support-Tabelle von pg-harden kennt 19 nicht. Das Support-Ende von 19 ist bei postgresql.org nicht veröffentlicht; der Eintrag wird nach der Veröffentlichung ergänzt, nicht geschätzt |

- `os.service_unit` und `os.package_source` sind im Container **nicht geprüft** (PID 1 ist kein systemd-Dienst, `/proc/1/exe` nicht
  lesbar) — auf allen Versionen gleich; die Tabelle weist sie so aus, nicht als `pass`. Am 24.10.2026 wurden dieselben Regeln mit
  Programmstand 0.3.0 auf einem Debian-13-System mit systemd (PostgreSQL 18, PGDG-Pakete) und auf Windows 11 (PostgreSQL 18) einzeln
  gefahren; diese Läufe sind nicht Teil dieser Tabelle.
- Nicht in dieser Matrix: Windows mit 14 bis 17, andere Linux-Familien als Debian/Alpine, Cluster mit Replikation.

## Status je Regel und Version

`pass` = ohne Befund · `fail` = Befund · `info` = Hinweis · `skip` = nicht anwendbar/übersprungen · `nicht geprüft` = ohne Befund, aber
nicht vollständig prüfbar. Die Spalten sind die Image-Tags.

| Regel | 14-trixie | 15-trixie | 16-trixie | 17-trixie | 18-trixie | 19rc1 |
|---|---|---|---|---|---|---|
| `auth.auth_delay` | fail | fail | fail | fail | fail | fail |
| `auth.authentication_timeout` | pass | pass | pass | pass | pass | pass |
| `auth.md5_passwords` | pass | pass | pass | pass | pass | pass |
| `auth.password_encryption` | pass | pass | pass | pass | pass | pass |
| `auth.password_policy` | fail | fail | fail | fail | fail | fail |
| `auth.weak_passwords` | pass | pass | pass | pass | pass | pass |
| `avail.archive_enabled` | fail | fail | fail | fail | fail | fail |
| `avail.archiver_failing` | pass | pass | pass | pass | pass | pass |
| `avail.inactive_slots` | pass | pass | pass | pass | pass | pass |
| `avail.slot_wal_keep` | pass | pass | pass | pass | pass | pass |
| `avail.temp_file_limit` | fail | fail | fail | fail | fail | fail |
| `code.extensions` | info | info | info | info | info | info |
| `code.lo_compat_privileges` | pass | pass | pass | pass | pass | pass |
| `code.preload_libraries` | info | info | info | info | info | info |
| `code.secdef_search_path` | pass | pass | pass | pass | pass | pass |
| `code.untrusted_languages` | pass | pass | pass | pass | pass | pass |
| `conf.role_db_overrides` | pass | pass | pass | pass | pass | pass |
| `data.checksums` | fail | fail | fail | fail | pass | pass |
| `db.catalog_visibility` | fail | fail | fail | fail | fail | fail |
| `db.public_connect` | fail | fail | fail | fail | fail | fail |
| `db.public_schema_create` | fail | pass | pass | pass | pass | pass |
| `db.public_temp` | fail | fail | fail | fail | fail | fail |
| `hba.cleartext_password` | pass | pass | pass | pass | pass | pass |
| `hba.errors` | pass | pass | pass | pass | pass | pass |
| `hba.host_without_tls` | fail | fail | fail | fail | fail | fail |
| `hba.md5_method` | pass | pass | pass | pass | pass | pass |
| `hba.open_to_all` | fail | fail | fail | fail | fail | fail |
| `hba.superuser_remote` | fail | fail | fail | fail | fail | fail |
| `hba.trust` | fail | fail | fail | fail | fail | fail |
| `log.collector` | fail | fail | fail | fail | fail | fail |
| `log.connections` | fail | fail | fail | fail | fail | fail |
| `log.debug_print` | pass | pass | pass | pass | pass | pass |
| `log.directory_outside_pgdata` | pass | pass | pass | pass | pass | pass |
| `log.disconnections` | fail | fail | fail | fail | fail | fail |
| `log.file_mode` | pass | pass | pass | pass | pass | pass |
| `log.line_prefix` | fail | fail | fail | fail | fail | fail |
| `log.parameter_length` | fail | fail | fail | fail | fail | fail |
| `log.pgaudit` | fail | fail | fail | fail | fail | fail |
| `log.statement_ddl` | fail | fail | fail | fail | fail | fail |
| `net.listen_addresses` | pass | pass | pass | pass | pass | pass |
| `os.config_permissions` | pass | pass | pass | pass | pass | pass |
| `os.disk_free` | pass | pass | pass | pass | pass | pass |
| `os.log_own_volume` | pass | pass | pass | pass | pass | pass |
| `os.log_permissions` | pass | pass | pass | pass | pass | pass |
| `os.package_source` | nicht geprüft | nicht geprüft | nicht geprüft | nicht geprüft | nicht geprüft | nicht geprüft |
| `os.pgdata_permissions` | pass | pass | pass | pass | pass | pass |
| `os.service_account` | pass | pass | pass | pass | pass | pass |
| `os.service_unit` | nicht geprüft | nicht geprüft | nicht geprüft | nicht geprüft | nicht geprüft | nicht geprüft |
| `os.socket_permissions` | fail | fail | fail | fail | fail | fail |
| `os.ssl_key_permissions` | pass | pass | pass | pass | pass | pass |
| `os.umask` | pass | pass | pass | pass | pass | pass |
| `patch.catalog_current` | pass | pass | pass | pass | pass | fail |
| `patch.supported_major` | fail | pass | pass | pass | pass | pass |
| `roles.allow_alter_system` | skip | skip | skip | fail | fail | fail |
| `roles.bypassrls` | pass | pass | pass | pass | pass | pass |
| `roles.createrole` | pass | pass | pass | pass | pass | pass |
| `roles.extra_superusers` | pass | pass | pass | pass | pass | pass |
| `roles.server_file_access` | pass | pass | pass | pass | pass | pass |
| `sess.idle_in_transaction` | fail | fail | fail | fail | fail | fail |
| `tls.min_protocol` | pass | pass | pass | pass | pass | pass |
| `tls.ssl_enabled` | fail | fail | fail | fail | fail | fail |

Statuswerte je Version:

- 14-trixie: fail 24, info 2, nicht geprüft 2, pass 32, skip 1
- 15-trixie: fail 22, info 2, nicht geprüft 2, pass 34, skip 1
- 16-trixie: fail 22, info 2, nicht geprüft 2, pass 34, skip 1
- 17-trixie: fail 23, info 2, nicht geprüft 2, pass 34
- 18-trixie: fail 22, info 2, nicht geprüft 2, pass 35
- 19rc1: fail 23, info 2, nicht geprüft 2, pass 34

Hinweise zu Fehlern und unvollständigen Prüfungen:

- `os.service_unit` (14-trixie): nicht geprüft: Umgebung des Serverprozesses nicht lesbar (/proc/1/environ — root bzw. Dienstkonto nötig) / Kein systemd-Dienst ermittelt — Dienstdatei nicht geprüft
- `os.service_unit` (15-trixie): nicht geprüft: Umgebung des Serverprozesses nicht lesbar (/proc/1/environ — root bzw. Dienstkonto nötig) / Kein systemd-Dienst ermittelt — Dienstdatei nicht geprüft
- `os.service_unit` (16-trixie): nicht geprüft: Umgebung des Serverprozesses nicht lesbar (/proc/1/environ — root bzw. Dienstkonto nötig) / Kein systemd-Dienst ermittelt — Dienstdatei nicht geprüft
- `os.service_unit` (17-trixie): nicht geprüft: Umgebung des Serverprozesses nicht lesbar (/proc/1/environ — root bzw. Dienstkonto nötig) / Kein systemd-Dienst ermittelt — Dienstdatei nicht geprüft
- `os.service_unit` (18-trixie): nicht geprüft: Umgebung des Serverprozesses nicht lesbar (/proc/1/environ — root bzw. Dienstkonto nötig) / Kein systemd-Dienst ermittelt — Dienstdatei nicht geprüft
- `os.service_unit` (19rc1): nicht geprüft: Umgebung des Serverprozesses nicht lesbar (/proc/1/environ — root bzw. Dienstkonto nötig) / Kein systemd-Dienst ermittelt — Dienstdatei nicht geprüft
- `os.package_source` (14-trixie): nicht geprüft: Programmdatei des Serverprozesses nicht ermittelbar (/proc/1/exe — root nötig)
- `os.package_source` (15-trixie): nicht geprüft: Programmdatei des Serverprozesses nicht ermittelbar (/proc/1/exe — root nötig)
- `os.package_source` (16-trixie): nicht geprüft: Programmdatei des Serverprozesses nicht ermittelbar (/proc/1/exe — root nötig)
- `os.package_source` (17-trixie): nicht geprüft: Programmdatei des Serverprozesses nicht ermittelbar (/proc/1/exe — root nötig)
- `os.package_source` (18-trixie): nicht geprüft: Programmdatei des Serverprozesses nicht ermittelbar (/proc/1/exe — root nötig)
- `os.package_source` (19rc1): nicht geprüft: Programmdatei des Serverprozesses nicht ermittelbar (/proc/1/exe — root nötig)
