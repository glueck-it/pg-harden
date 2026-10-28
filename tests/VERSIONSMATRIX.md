# Versionsmatrix PostgreSQL 14 bis 19 (Stand 28.10.2026, Programmstand 0.4.0 unveröffentlicht)

Getestet mit `tests/run-version-matrix.sh`: je Version ein Container (`postgres:14-trixie` … `postgres:18-trixie`, `postgres:19rc1`,
Debian 13, PHP 8.4.27, als root im Container, Datenverzeichnis lokal, Vertrauensanmeldung wie in `lab/`). Die Versionen meldete der
Server selbst (`show server_version`): 14.24, 15.19, 16.15, 17.11, 18.6 und 19rc1 — jeweils der Stand der Image-Tags am 26.10.2026,
am 28.10.2026 unverändert. Mit Programmstand 0.3.0 (24.10.2026), 0.3.1 (25.10.2026) und 0.3.2 (26.10.2026) ergab die Matrix dieselbe
Statustabelle; mit 0.4.0 (28.10.2026) kommen nur die Zeilen der neuen Regeln hinzu, die übrigen sind unverändert.
PostgreSQL 19 ist ein Release Candidate; die Veröffentlichung ist laut der Ankündigung von RC 1 auf postgresql.org (Stand 24.10.2026)
für den 19.11.2026 geplant. Die Spalte 19rc1 ist eine Vorabprüfung, kein Freigabevermerk.

Die Matrix zeigt **Lauffähigkeit und Versionsunterschiede, keine Wirksamkeit der Regeln**: `pass` heißt „kein Befund in dieser frischen
Container-Konfiguration“, nicht „die Regel erkennt Fehler zuverlässig“.

## Ergebnis

- **Kein Fehlerstatus** in `check` auf keiner Version; die Fehlerausgabe ist überall leer.
- **Regressionsläufe** (`tests/lab-matrix.sh`, T1–T15: `apply`/`rollback` von Konfiguration, `pg_hba.conf` mit Aussperrschutz, SQL,
  manipuliertes Journal, entfernte Verbindung, Katalog-Sichtbarkeit, `rollback` mit geschlossener Ausgabe, wiederholter `rollback` nach
  einem unvollständigen mit und ohne Neuladen (T13, T13b), Identität beim Schreiben und Lesen als root mit Links des Dienstkontos,
  Sticky-Verzeichnis, Hardlink, FIFO und Gerät (T14, `tests/lab-identity.php`), `check` als root mit gefälschter Prozessnummer und FIFO
  in `postmaster.pid` (T15)) und **Sichtbarkeitsprobe** (`tests/lab-visibility.sh`) liefern auf
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
| `roles.createrole_self_grant` | übersprungen in 14–15 | Parameter gibt es ab 16 (`min_version`) |
| `log.lock_waits` | Befund in 14–18, ok in 19rc1 | `log_lock_waits` steht im 19rc1-Container ab Werk auf `on` (gemessen), davor auf `off` |
| `patch.supported_major` | Befund in 14 | Support endet am 12.11.2026 (Fenster von 90 Tagen) |
| `patch.catalog_current` | Befund in 19rc1 | Katalog-Stand: die Support-Tabelle von pg-harden kennt 19 nicht. Das Support-Ende von 19 ist bei postgresql.org nicht veröffentlicht; der Eintrag wird nach der Veröffentlichung ergänzt, nicht geschätzt |

- `os.service_unit` und `os.package_source` sind im Container **nicht geprüft** (PID 1 ist kein systemd-Dienst, `/proc/1/exe` nicht
  lesbar) — auf allen Versionen gleich; die Tabelle weist sie so aus, nicht als `pass`. Am 24.10.2026 wurden dieselben Regeln mit
  Programmstand 0.3.0 auf einem Debian-13-System mit systemd (PostgreSQL 18, PGDG-Pakete) und auf Windows 11 (PostgreSQL 18) einzeln
  gefahren; diese Läufe sind nicht Teil dieser Tabelle. Am 25.10.2026 liefen `apply` und `rollback` mit Programmstand 0.3.1 zusätzlich
  einzeln auf dem Paket-Layout von Debian 13 (PostgreSQL 17 aus den Debian-Paketen, Konfiguration unter `/etc/postgresql/17/main` im
  Besitz von `postgres`, Container ohne systemd). Am 26.10.2026 liefen `check`, `apply`, `rollback` und ein wiederholter `rollback` nach
  einem nachgestellten Abbruch mit Programmstand 0.3.1 auf Windows 11 (PostgreSQL 18.6, Wegwerf-Cluster mit `initdb`), am selben Tag
  `check` mit Programmstand 0.3.2 dort normal und mit einer gefälschten Prozessnummer in `postmaster.pid` (als nicht nachgewiesen
  gemeldet, der fremde Prozess nicht gelesen).
- **Programmstand 0.4.0 (unveröffentlicht), 28.10.2026:**
  - `tests/windows-redirect.php` auf Windows 11 (Wegwerf-Ordner unter `%TEMP%`, ohne Administratorrechte), 61 Fälle grün:
    Wegprüfung für `client --user` und `check` (auch `postmaster.pid` im Datenverzeichnis), ACL über das offene Handle
    (`GetSecurityInfo`/`GetFinalPathNameByHandleW`), Verzeichnissperre `WindowsPin` (ohne `FILE_SHARE_DELETE`; dass leere
    Verzeichnisse auch ohne `FILE_SHARE_WRITE` gehalten werden, ist Bauart, das Umwandeln an Ort und Stelle ist nicht nachgestellt) für
    `ServerFiles::overwrite`, `create`, `makeDir`, `restore` und `Journal::backup` gegen Junctions,
    Umbenennen im festgehaltenen Datenverzeichnis weiter möglich, Abbruch ohne aktive Sperre und nach beendetem Helfer,
    Wiederherstellung nach beendetem Helfer und über `Guard::onShutdown`, enge ACL des Journal-Verzeichnisses. `--out` über eine
    vorhandene Datei einzeln geprüft (neue Datei mit enger ACL, keine Temp-Datei zurück).
  - `tests/windows-admin-test.ps1` (lokales Testkonto ohne Administratorrechte, nur in einer Administrator-PowerShell) liegt bereit
    und ist **noch nicht gelaufen**.
  - Regelkatalog mit 86 Regeln: neu `tls.ciphers`, `hba.weak_options`, `auth.passwordless_or_expired`, `roles.replication_login`,
    `roles.createrole_self_grant`, `db.default_acl_public`, `db.rls_policies_inactive`, `code.fdw_secrets`, `code.event_triggers`,
    `log.lock_waits`, `data.crash_safety`, `os.ssl_cert_expiry`, `os.tablespace_permissions`, `client.psql_history`; erweitert
    `conf.role_db_overrides`, `roles.server_file_access`, `log.pgaudit`, `os.config_permissions`, `os.service_unit`. In der Matrix
    unten (frische Container) laufen sie ohne Fehler; erkannt werden Befunde nur, wo es welche gibt. Deshalb zusätzlich gegen die
    Übungsinstanz (`lab/`, PostgreSQL 18 Alpine, mit nachträglich eingerichteten Fällen: `ident` über das Netz und über
    `127.0.0.1`, LDAP-Zeile mit `clientcert=verify-ca` und Bindungspasswort, `REPLICATION` mit und ohne `LOGIN`, `ssl_ciphers` mit
    `RC4-SHA`, Event-Trigger): Befunde wie erwartet, `ident` über `127.0.0.1` und die Rolle ohne `LOGIN` ohne Befund, das
    Bindungspasswort steht nicht im Bericht, `db.rls_policies_inactive` meldet die Tabelle mit RLS ohne Policy.
  - Ebenfalls neu: vorläufige Zuordnungen zu BSI `APP.4.3` und CIS PostgreSQL Benchmark (Kennungen ungeprüft), `verify` für
    Client-Berichte, enge Windows-ACLs für Journale und Ausgabedateien, `tests/catalog-test.php`.
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
| `auth.passwordless_or_expired` | pass | pass | pass | pass | pass | pass |
| `auth.weak_passwords` | pass | pass | pass | pass | pass | pass |
| `avail.archive_enabled` | fail | fail | fail | fail | fail | fail |
| `avail.archiver_failing` | pass | pass | pass | pass | pass | pass |
| `avail.inactive_slots` | pass | pass | pass | pass | pass | pass |
| `avail.slot_wal_keep` | pass | pass | pass | pass | pass | pass |
| `avail.temp_file_limit` | fail | fail | fail | fail | fail | fail |
| `code.event_triggers` | info | info | info | info | info | info |
| `code.extensions` | info | info | info | info | info | info |
| `code.fdw_secrets` | pass | pass | pass | pass | pass | pass |
| `code.lo_compat_privileges` | pass | pass | pass | pass | pass | pass |
| `code.preload_libraries` | info | info | info | info | info | info |
| `code.secdef_search_path` | pass | pass | pass | pass | pass | pass |
| `code.untrusted_languages` | pass | pass | pass | pass | pass | pass |
| `conf.role_db_overrides` | pass | pass | pass | pass | pass | pass |
| `data.checksums` | fail | fail | fail | fail | pass | pass |
| `data.crash_safety` | pass | pass | pass | pass | pass | pass |
| `db.catalog_visibility` | fail | fail | fail | fail | fail | fail |
| `db.default_acl_public` | pass | pass | pass | pass | pass | pass |
| `db.public_connect` | fail | fail | fail | fail | fail | fail |
| `db.public_schema_create` | fail | pass | pass | pass | pass | pass |
| `db.public_temp` | fail | fail | fail | fail | fail | fail |
| `db.rls_policies_inactive` | pass | pass | pass | pass | pass | pass |
| `hba.cleartext_password` | pass | pass | pass | pass | pass | pass |
| `hba.errors` | pass | pass | pass | pass | pass | pass |
| `hba.host_without_tls` | fail | fail | fail | fail | fail | fail |
| `hba.md5_method` | pass | pass | pass | pass | pass | pass |
| `hba.open_to_all` | fail | fail | fail | fail | fail | fail |
| `hba.superuser_remote` | fail | fail | fail | fail | fail | fail |
| `hba.trust` | fail | fail | fail | fail | fail | fail |
| `hba.weak_options` | pass | pass | pass | pass | pass | pass |
| `log.collector` | fail | fail | fail | fail | fail | fail |
| `log.connections` | fail | fail | fail | fail | fail | fail |
| `log.debug_print` | pass | pass | pass | pass | pass | pass |
| `log.directory_outside_pgdata` | pass | pass | pass | pass | pass | pass |
| `log.disconnections` | fail | fail | fail | fail | fail | fail |
| `log.file_mode` | pass | pass | pass | pass | pass | pass |
| `log.line_prefix` | fail | fail | fail | fail | fail | fail |
| `log.lock_waits` | fail | fail | fail | fail | fail | pass |
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
| `os.ssl_cert_expiry` | pass | pass | pass | pass | pass | pass |
| `os.ssl_key_permissions` | pass | pass | pass | pass | pass | pass |
| `os.tablespace_permissions` | pass | pass | pass | pass | pass | pass |
| `os.umask` | pass | pass | pass | pass | pass | pass |
| `patch.catalog_current` | pass | pass | pass | pass | pass | fail |
| `patch.supported_major` | fail | pass | pass | pass | pass | pass |
| `roles.allow_alter_system` | skip | skip | skip | fail | fail | fail |
| `roles.bypassrls` | pass | pass | pass | pass | pass | pass |
| `roles.createrole` | pass | pass | pass | pass | pass | pass |
| `roles.createrole_self_grant` | skip | skip | pass | pass | pass | pass |
| `roles.extra_superusers` | pass | pass | pass | pass | pass | pass |
| `roles.replication_login` | pass | pass | pass | pass | pass | pass |
| `roles.server_file_access` | pass | pass | pass | pass | pass | pass |
| `sess.idle_in_transaction` | fail | fail | fail | fail | fail | fail |
| `tls.ciphers` | pass | pass | pass | pass | pass | pass |
| `tls.min_protocol` | pass | pass | pass | pass | pass | pass |
| `tls.ssl_enabled` | fail | fail | fail | fail | fail | fail |

Statuswerte je Version:

- 14-trixie: fail 25, info 3, nicht geprüft 2, pass 42, skip 2
- 15-trixie: fail 23, info 3, nicht geprüft 2, pass 44, skip 2
- 16-trixie: fail 23, info 3, nicht geprüft 2, pass 45, skip 1
- 17-trixie: fail 24, info 3, nicht geprüft 2, pass 45
- 18-trixie: fail 23, info 3, nicht geprüft 2, pass 46
- 19rc1: fail 23, info 3, nicht geprüft 2, pass 46

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
