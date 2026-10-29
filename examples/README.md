# Examples — real output of pg-harden

**English** · [Deutsch](#beispiele--echte-ausgaben-von-pg-harden)

Everything in [`output/`](output/) was produced by pg-harden 0.4.1 against a throw-away PostgreSQL 18 container with a deliberately weak,
"grown" configuration ([`sample-init.sql`](sample-init.sql): an md5 password left over from an old version, an application role with an obvious
password, `PUBLIC` allowed to create objects in `public`, a `SECURITY DEFINER` function without a fixed `search_path`, `trust` in `pg_hba.conf`).
Nothing was edited by hand. [`generate.sh`](generate.sh) recreates all files (Docker required). The tool's output is in German.

These reports are published only because the instance is fictional. Real reports contain role, object and network names — keep them confidential.

| File | What it shows |
|---|---|
| [`01-check.txt`](output/01-check.txt) | `check` — the report in the terminal: header and summary, findings by severity (high → low), rules to review, incomplete and clean rules, the ISO 27001 overview, and the notices at the end |
| [`01-check.html`](output/01-check.html) | the same report as HTML, written with `-o 01-check.html` (download and open in a browser) |
| [`02-plan.txt`](output/02-plan.txt) | `plan` — writes the change plan as files, changes nothing on the server |
| [`02-plan/90-pg-harden.conf`](output/02-plan/90-pg-harden.conf) | parameters for `conf.d`; `#BESTÄTIGEN` lines are commented out until you enable them |
| [`02-plan/harden_shop.sql`](output/02-plan/harden_shop.sql) | SQL fixes for database `shop`, each with its way back (`-- Rückweg:`); fixes of level `confirm` are commented out (`-- BESTÄTIGEN:`) until you enable them |
| [`02-plan/MANUELL.md`](output/02-plan/MANUELL.md) | findings to resolve by hand or with `apply --include-confirm` (`pg_hba.conf`, passwords, roles …) |
| [`02-plan/report.json`](output/02-plan/report.json) | baseline report for the comparison (`check -f /root/plan/report`) |
| [`03-apply-dry-run.txt`](output/03-apply-dry-run.txt) | `apply` without `--execute` — what would happen, nothing changed |
| [`04-apply.txt`](output/04-apply.txt) | `apply --execute` — validation by the server, reload, new login test, SQL, then before/after comparison |
| [`04-apply-log.json`](output/04-apply-log.json), [`04-journal-files.txt`](output/04-journal-files.txt) | the journal: every step, the backups and the stored way back |
| [`04-written-90-pg-harden.conf`](output/04-written-90-pg-harden.conf) | the file `apply` wrote into `conf.d` |
| [`05-compare.txt`](output/05-compare.txt), [`05-compare.html`](output/05-compare.html) | `check -f` — new report plus comparison with the baseline (fixed / new / still open) |
| [`06-rollback.txt`](output/06-rollback.txt) | `rollback` — backups restored, reload, login test, SQL way back |
| [`07-apply-hba-refused.txt`](output/07-apply-hba-refused.txt) | lockout protection: switching `pg_hba.conf` from `trust` to `scram-sha-256` is refused because roles have no SCRAM password |
| [`07-pg_hba-checksum-before.txt`](output/07-pg_hba-checksum-before.txt), [`07-pg_hba-checksum-after.txt`](output/07-pg_hba-checksum-after.txt) | checksums of `pg_hba.conf` taken directly before and after that step — identical, the file was not touched |
| [`08-rules.txt`](output/08-rules.txt) | `rules` — the rule catalog with severity and level |
| [`09-client.txt`](output/09-client.txt), [`09-client.html`](output/09-client.html) | `client` — audit of the machine you connect from (here: the container itself) |

The passwords in `sample-init.sql` are weak or public — never use them anywhere else.

---

# Beispiele — echte Ausgaben von pg-harden

[English](#examples--real-output-of-pg-harden) · **Deutsch**

Alle Dateien in [`output/`](output/) hat pg-harden 0.4.1 gegen einen Wegwerf-Container mit PostgreSQL 18 erzeugt, dessen Konfiguration absichtlich
schwach und „gewachsen“ ist ([`sample-init.sql`](sample-init.sql): ein md5-Passwort aus einer alten Version, eine Anwendungsrolle mit naheliegendem
Passwort, `PUBLIC` darf in `public` anlegen, eine `SECURITY DEFINER`-Funktion ohne festen `search_path`, `trust` in `pg_hba.conf`). Nichts ist von
Hand bearbeitet. [`generate.sh`](generate.sh) erzeugt alle Dateien neu (Docker nötig).

Diese Berichte sind nur veröffentlicht, weil die Instanz fiktiv ist. Echte Berichte enthalten Rollen-, Objekt- und Netznamen — vertraulich behandeln.

| Datei | Was sie zeigt |
|---|---|
| [`01-check.txt`](output/01-check.txt), [`01-check.html`](output/01-check.html) | `check` — Kopf und Zusammenfassung, Befunde nach Schwere (hoch → niedrig), zu Sichtendes, Unvollständiges, Regeln ohne Befund, ISO-27001-Übersicht und Hinweise am Ende; HTML mit `-o 01-check.html` geschrieben (herunterladen und im Browser öffnen) |
| [`02-plan.txt`](output/02-plan.txt), [`02-plan/`](output/02-plan/) | `plan` — Änderungsplan als Dateien: `90-pg-harden.conf`, `harden_<db>.sql` mit Rückweg je Korrektur (Korrekturen der Stufe `confirm` als `-- BESTÄTIGEN:` auskommentiert), `MANUELL.md` (von Hand oder mit `apply --include-confirm` zu erledigen), `report.json` (Ausgangsbericht für `check -f`) |
| [`03-apply-dry-run.txt`](output/03-apply-dry-run.txt) | `apply` ohne `--execute` — was geschähe, nichts geändert |
| [`04-apply.txt`](output/04-apply.txt), [`04-apply-log.json`](output/04-apply-log.json), [`04-journal-files.txt`](output/04-journal-files.txt), [`04-written-90-pg-harden.conf`](output/04-written-90-pg-harden.conf) | `apply --execute` — Prüfung durch den Server, Neuladen, Anmeldetest, SQL, Vorher/Nachher-Vergleich und das Journal |
| [`05-compare.txt`](output/05-compare.txt), [`05-compare.html`](output/05-compare.html) | `check -f` — neuer Bericht und Vergleich mit dem Ausgangsbericht (behoben / neu / weiter offen) |
| [`06-rollback.txt`](output/06-rollback.txt) | `rollback` — Sicherungen zurück, Neuladen, Anmeldetest, SQL-Rückweg |
| [`07-apply-hba-refused.txt`](output/07-apply-hba-refused.txt), [`07-pg_hba-checksum-before.txt`](output/07-pg_hba-checksum-before.txt), [`07-pg_hba-checksum-after.txt`](output/07-pg_hba-checksum-after.txt) | Schutz vor dem Aussperren: `trust` → `scram-sha-256` wird abgelehnt, solange Rollen kein SCRAM-Passwort haben; die Prüfsummen direkt davor und danach sind gleich |
| [`08-rules.txt`](output/08-rules.txt) | `rules` — der Regelkatalog mit Schweregrad und Stufe |
| [`09-client.txt`](output/09-client.txt), [`09-client.html`](output/09-client.html) | `client` — Prüfung des Rechners, von dem aus verbunden wird (hier: der Container selbst) |

Die Passwörter in `sample-init.sql` sind schwach oder öffentlich — nirgends sonst verwenden.
