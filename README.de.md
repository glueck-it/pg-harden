# pg-harden — Prüf- und Härtungswerkzeug für PostgreSQL

[English](README.md) · **Deutsch**

Prüft eine PostgreSQL-Instanz gegen einen Regelkatalog, schreibt einen Änderungsplan, vergleicht Vorher/Nachher-Berichte,
prüft den Rechner, von dem aus verbunden wird, und führt auf ausdrücklichen Befehl ausgewählte Korrekturen mit Sicherung
und Rückweg aus.

Geprüft werden `postgresql.conf`, `pg_hba.conf`, TLS, SCRAM-SHA-256, schwache Passwörter, Rollen und Rechte, `PUBLIC`-Rechte, `SECURITY DEFINER`-Funktionen,
Protokollierung und die Betriebssystemseite (Dateirechte, Dienstkonto) von PostgreSQL 14 bis 18 und 19 RC1 — 86 Regeln (74 für `check`, 12 für `client`), ein PHP-Werkzeug
ohne Composer-Abhängigkeiten (PHP 8.3 mit `pdo_pgsql` und `mbstring`). Getestet mit PostgreSQL 14 bis 18 und 19rc1 (Docker, Debian 13) sowie PostgreSQL 18 unter Windows 11
([tests/VERSIONSMATRIX.md](tests/VERSIONSMATRIX.md)) — die Matrix zeigt Lauffähigkeit und Versionsunterschiede, nicht die Erkennungsgüte der Regeln. Gepflegt von [Frank Glück](https://dozent.net) — Datenbankberater, Entwickler und Dozent. Impressum: <https://dozent.net/informationen/impressum>.

**`check`, `plan`, `client` und `rules` schreiben nichts auf den Server.** Jede Datenbankprüfung läuft als einzelne
vorbereitete Anweisung in `BEGIN TRANSACTION READ ONLY … ROLLBACK`, mit `search_path = pg_catalog, pg_temp` und Zeitlimits.
Hinter einem PgBouncer im Transaction-Pooling gelten Sitzungseinstellungen nicht zuverlässig — direkt verbinden. Nur
`apply` und `rollback` schreiben, und nur mit `--execute` bzw. gegen ein Journal (siehe unten).

## Bestimmungsgemäße Verwendung

> pg-harden ist zur Härtung eigener oder ausdrücklich beauftragter Systeme bestimmt. Die Passwortprüfung liest
> `pg_authid` nur mit Superuser-Recht, rechnet eine kleine, fest umrissene Liste naheliegender Kandidaten sowie optional eine vom Betreiber bereitgestellte,
> auf 100 Einträge begrenzte Liste betriebsspezifischer Begriffe nach (keine Wörterbücher, kein Brute-Force), erzeugt keine Fehlanmeldungen und gibt nie ein Passwort aus —
> nur die Tatsache, dass eine Rolle einen Wert aus der Prüfliste verwendet. Der Client-Modus mit `--user` liest
> Dateien und Umgebungen anderer Benutzerkonten und setzt Administrator- bzw. root-Rechte **und** die Berechtigung
> voraus, diese Konten zu prüfen; gefundene Geheimnisse erscheinen nur mit Fundstelle und Zeile. Berichte können
> rollenbezogene und damit personenbeziehbare Befunde enthalten: vertraulich behandeln, nur zur Behebung verwenden,
> zeitnah löschen; wo Rollen Beschäftigten zugeordnet sind, Datenschutz und Mitbestimmung beachten. Eine Nutzung auf
> fremden Systemen oder Konten ohne Berechtigung ist bestimmungswidrig.

Derselbe Text steht in `--help` und im abgesetzten Block „Hinweise“ am Ende jedes Berichts, der Passwort- oder Client-Ergebnisse enthält.

## Selbst prüfen — ohne Gewähr

pg-harden ist ein Hilfsmittel, keine Freigabe. Die Software wird unter der MIT-Lizenz ohne jede Gewähr
bereitgestellt (siehe `LICENSE`).

- Befunde fachlich bewerten: nicht jeder Befund ist in jeder Umgebung ein Mangel, und nicht jeder Mangel hat
  eine Regel im Katalog.
- Ein Lauf ohne Befund heißt nur, dass die Regeln des Katalogs nichts gefunden haben — nicht, dass die Instanz
  sicher ist.
- Pläne sind Vorschläge. Jede Änderung selbst prüfen, in einer Testumgebung erproben und erst dann in Produktion
  einspielen. `apply` führt aus, was du freigibst — mit Sicherung und Rückweg, aber ohne Garantie für deine Anwendungen.
- Die Zuordnung zu Normen ist keine Aussage über deren Erfüllung.

Eine Kurzfassung dieses Hinweises steht in `--help`, am Ende jedes Berichts und in jeder Plan-Datei.

## Voraussetzungen

- PHP 8.3+ mit `pdo_pgsql` und `mbstring` (für die Zertifikatsprüfung von `client` zusätzlich `openssl`,
  unter Linux für `--user` und Dateirechte `posix`; außerhalb von Windows brauchen `apply` und `rollback` für Dateiänderungen `pcntl`
  und `posix`), keine weiteren Abhängigkeiten
- Windows: Windows PowerShell 5.1 (liegt dem System bei) für ACLs, Dienstkonto und Aufgabenplanung
- Passwort über `PGPASSWORD` oder die pgpass-Datei — nie auf der Kommandozeile
- Rechte: Superuser für den vollen Umfang. Mit weniger Rechten laufen fast alle Regeln; ausgelassene werden
  als „übersprungen“ und „unvollständig“ gemeldet. Ausnahme: fehlt `SELECT` auf `pg_database` (nach `db.catalog_visibility`),
  bricht der Lauf ab, weil die Datenbankliste fehlt:

```sql
CREATE ROLE pgharden LOGIN;                                        -- der Präfix pg_ ist für Systemrollen reserviert
GRANT pg_monitor TO pgharden;                                      -- enthält pg_read_all_settings
GRANT EXECUTE ON FUNCTION pg_hba_file_rules() TO pgharden;         -- Regeln zu pg_hba.conf: Funktion ...
GRANT SELECT ON pg_hba_file_rules TO pgharden;                     -- ... und View
-- nur auth.md5_passwords und auth.weak_passwords brauchen Superuser (pg_authid)
-- Nach db.catalog_visibility (siehe unten) zusätzlich, in jeder Datenbank:
-- GRANT SELECT ON TABLE pg_catalog.pg_database, pg_catalog.pg_roles TO pgharden;
```

## Befehle

```bash
php pg-harden.php check  --host=db1 --user=postgres                       # Bericht im Terminal
php pg-harden.php check  --host=db1 --user=postgres -o audit.%y%m%d        # schreibt audit.261028.json und audit.261028.html
php pg-harden.php check  --host=db1 --user=postgres -f audit.261021 -o audit.261028   # Vergleich: behoben, neu, weiter offen
php pg-harden.php plan   --host=db1 --user=postgres --dir=plan-2026-10-23  # neues Verzeichnis, schreibt nur Dateien
php pg-harden.php client [--user=konto] [--scan=/opt/backup,/srv/compose]  # Rechner prüfen, keine Datenbankverbindung
php pg-harden.php apply  --host=db1 --user=postgres                        # Trockenlauf: zeigt, was geschähe
php pg-harden.php apply  --host=db1 --user=postgres --execute --dir=apply-2026-10-24 [--yes]
php pg-harden.php rollback --host=db1 --user=postgres --dir=apply-2026-10-24
php pg-harden.php check  --host=db1 --user=postgres --extra-candidates=extra-candidates.txt   # + eigene Begriffe (max. 100)
php pg-harden.php rules
```

**Bericht und Vergleich** (`check` und `client`): ohne `-o` erscheint der Bericht als Text im Terminal. `-o NAME` (`--output`)
schreibt `NAME.json` und `NAME.html`, das Terminal nennt dann nur die Dateien und die Zahl der Befunde. Endet der Name auf `.json`,
`.html`, `.htm` oder `.txt`, entsteht nur diese eine Datei; jeder andere Punkt gehört zum Namen (`-o audit.261028`). `-f NAME`
(`--file`) vergleicht mit einem früheren Bericht und liest `NAME.json` — der Name des früheren Laufs mit eingesetztem Datum
(`-f audit.261021`, nicht `audit.%y%m%d`); vergleichbar ist nur ein Lauf, der JSON geschrieben hat. Vorhandene Dateien gleichen Namens
werden ersetzt — ein zweiter Lauf mit `-o audit.%y%m%d` am selben Tag ersetzt den ersten (dann `%H%M` dazunehmen).

Datum und Uhrzeit im Namen setzen Platzhalter wie bei `log_filename` von PostgreSQL ein: `%Y` `%y` `%m` `%d` `%H` `%M` `%S`, `%%` für ein
Prozentzeichen — `-o audit.%y%m%d` ergibt `audit.261028.json` und `.html`. Es gilt der Beginn des Laufs (Zeitzone von PHP,
`date.timezone`). In einer Windows-`.bat`-Datei ist jedes `%` zu verdoppeln (`-o audit.%%y%%m%%d`). Wer das Datum lieber von der Shell
einsetzen lässt: `-o audit.$(date +%y%m%d)` (bash) bzw. `-o "audit.$(Get-Date -f yyMMdd)"` (PowerShell).

Der HTML-Bericht ist eine einzige Datei ohne externe Ressourcen und ohne Skript — die Gliederung des Textberichts mit einer Übersicht
oben, Farbe je Schwere, Druckvorlage und Dunkelmodus. Eine Content-Security-Policy lässt nur das eingebettete Stylesheet zu; jeder Wert
vom Server oder aus einem früheren Bericht wird maskiert.

**Genau sehen, was entsteht:** [examples/](examples/) enthält die echten Ausgaben aller Befehle gegen eine Beispielinstanz — Bericht (Text und
HTML), Plan-Dateien, Probelauf, `apply` mit Journal, Vergleich, `rollback`, `rules`, `client` und den Aussperrschutz, der eine Änderung an
`pg_hba.conf` ablehnt.

Verbindung: `--host`, `--port`, `--user`, `--dbname` (Einstieg, Standard `postgres`), `--sslmode`, `--databases=a,b`.
Wie bei psql gehen auch `-h`, `-p`, `-U`, `-d` und `--username` — lang `--host=db1` oder `--host db1`, kurz `-h db1`
oder `-hdb1` (ohne `=`): `php pg-harden.php check -h db1 -U postgres`. `-U` und `--username` sind immer der
Datenbankbenutzer; bei `client` nennt `--user` ein Konto des Rechners. Hilfe: `--help` oder `-?` (`-h` ist wie bei psql der Host).
Ohne `--host`/`--port` gelten die libpq-Vorgaben (`PGHOST`, `PGPORT`, Socket). Für entfernte Hosts ist
`sslmode=require` voreingestellt; `verify-full` ist vorzuziehen.

Exit-Codes: `0` keine Befunde · `1` Befunde · `3` keine Befunde, aber nicht alles geprüft (fehlende Rechte,
Fehler, ausgelassene oder gesperrte Datenbanken; beim Vergleich mit `-f` auch abweichender Server, Benutzer oder Umfang) ·
`2` Abbruch (auch unbekannte Optionen; bei `apply`/`rollback` ein fehlgeschlagener Lauf).

Ohne Zertifikatsprüfung (`verify-full`) meldet der Bericht bei entfernten Hosts einen Hinweis.

## Der Plan

Der Plan ist ein **automatisch erzeugter Vorschlag**. Auswirkungen auf Anwendungen vor dem Ausführen in einer
Testumgebung prüfen.

| Datei | Inhalt |
|---|---|
| `90-pg-harden.conf` | Parameter für `include_dir 'conf.d'` (am Ende von `postgresql.conf`). Warnt, wenn ein Wert von der Kommandozeile, aus `postgresql.auto.conf` oder per `ALTER DATABASE/ROLE … SET` kommt und die Datei deshalb nicht greift |
| `harden_<db>.sql` | SQL-Korrekturen je Datenbank in einer Transaktion, je Korrektur mit Rückweg als Kommentar. Die erste Anweisung bricht ab, wenn die Datei in einer anderen Datenbank läuft. Mit der Zieldatenbank selbst verbinden und mit `psql -v ON_ERROR_STOP=1 -f <datei>` einspielen — der Plan nennt bewusst keine fertige Befehlszeile mit dem Datenbanknamen (psql liest Namen mit `=` als Verbindungsangabe) |
| `MANUELL.md` | Befunde ohne automatische Korrektur (auch `pg_hba.conf`-Änderungen, die nur `apply` ausführt), nicht planbare Objekte, nicht vollständig geprüfte Regeln |
| `report.json` | Ausgangsbericht zum Vergleich: `check -f plan-2026-10-23/report` |

Stufen je Regel: `auto` (geringes Betriebsrisiko, aktiv im Plan), `confirm` (auskommentiert, bewusst
freischalten), `manual` (nur in `MANUELL.md`). Objekte mit Steuer- oder Formatzeichen im Namen (auch
Bidi-Zeichen) und Korrektur-SQL mit Zeichen, die psql auswerten würde, werden nie in eine SQL-Datei geschrieben.
Das Plan-Verzeichnis muss neu oder leer sein und dem aufrufenden Benutzer gehören; Dateien werden exklusiv
angelegt, bei einem Abbruch wird nichts Halbfertiges zurückgelassen.

Der Vergleich (`-f`) wertet einen früheren Befund nur dann als behoben, wenn genau diese Stelle — bei Datenbank-Befunden
genau diese Datenbank — im aktuellen Lauf erneut geprüft wurde; sonst erscheint er als „nicht vergleichbar“.

## `apply` — Plan ausführen, mit Schutz vor dem Aussperren

`apply` ist der einzige Befehl, der den Server verändert. Ohne `--execute` zeigt er nur, was er tun würde.

- **Auswahl:** ausgeführt werden Regeln der Stufe `auto`. Regeln der Stufe `confirm` brauchen ihre Kennung in
  `--include-confirm=ID,ID` — eine Sammelfreigabe gibt es nicht. `--rules=ID,ID` beschränkt den Lauf.
- **Verbindung:** Schreiben (`apply --execute`, `rollback`) über eine entfernte Verbindung geht nur mit `--sslmode=verify-full`
  (`verify-ca` prüft den Rechnernamen nicht); ohne diese Prüfung bricht `apply` ab. Dasselbe gilt für die Passwortprüfung in `check` (sie liest die Verifier).
- **Konfigurationsdateien** (`postgresql.conf`, `pg_hba.conf`) kann `apply` nur ändern, wenn es **auf dem Server selbst**
  läuft (Beleg: `postmaster.pid` dieses Rechners gehört zur verbundenen Instanz) und die Schreibrechte hat
  (Dienstkonto bzw. Administrator/root). Sonst werden diese Aktionen mit Begründung übersprungen; SQL-Korrekturen
  laufen auch aus der Ferne.
- **Parameter** gehen nach `conf.d/90-pg-harden.conf`; fehlt ein aktives `include_dir`, ergänzt `apply` es am Ende
  von `postgresql.conf` (Sicherung inklusive). Werte, die von der Kommandozeile des Servers oder aus
  `postgresql.auto.conf` überschrieben würden, werden nicht geschrieben. Parameter mit Neustart werden geschrieben
  und gemeldet — **`apply` startet den Server nie neu.**
- **`pg_hba.conf`:** es ändert sich nur das eine Feld (Methode `trust`/`md5`/`password` → `scram-sha-256`, `host` →
  `hostssl`), Kommentare und Abstände bleiben. `local`-Zeilen fasst `apply` nie an — der Zugang über den
  Unix-Socket bleibt. Vorbedingungen gegen Aussperren: alle anmeldefähigen Rollen haben ein SCRAM-Passwort
  (bei `trust` auch: ein Passwort überhaupt), bei `hostssl` ist `ssl` an.
- **Ablauf der Dateiänderung:** Sicherung ins Journal → schreiben (am Ort, Besitzer und Rechte bleiben) → der Server prüft
  die Dateien auf der Platte (`pg_hba_file_rules`, `pg_file_settings`; jede Abweichung vom erwarteten Ergebnis, jeder
  Fehler führt zur Wiederherstellung **ohne** Neuladen) → `pg_reload_conf()` → **neue** Anmeldung mit denselben
  Zugangsdaten (bestehende Sitzungen überleben eine kaputte `pg_hba.conf` und beweisen nichts) → bei Misserfolg
  Sicherungen zurück, erneut laden, erneut prüfen.
- **Dateizugriff als root bzw. Administrator:** unter Linux/Unix arbeitet root an einem Pfad nur selbst, solange jedes Verzeichnis auf dem Weg root gehört und niemand sonst
  hineinschreiben kann. Ab dem ersten Verzeichnis eines anderen Kontos (meist des Dienstkontos) arbeiten `apply` und `rollback` mit dessen
  Identität und dessen eigenen Gruppen. Das ist so gebaut, dass ein vom Dienstkonto untergeschobener Link oder ein umbenanntes Verzeichnis
  nicht über dessen Rechte hinausreicht, auch wenn dies erst zwischen Prüfung und Schreiben geschieht (Test T14). Lesezugriffe für eine
  Änderung gehen denselben Weg (nur reguläre Dateien, mit Größengrenze). Ein Verzeichnis von root auf dem Weg, in das Gruppe oder andere
  schreiben können, wird abgewiesen; die Identität für jedes Ziel steht vor der ersten Änderung fest. `postgresql.conf` wird für die Änderung nur
  einmal gelesen; `apply` legt höchstens eine Verzeichnisebene an. Eine Datei von root in einem Verzeichnis des Dienstkontos wird an Ort und
  Stelle geschrieben, wenn das Dienstkonto sie beschreiben darf, sonst abgewiesen. Windows kennt keinen Identitätswechsel:
  dort hält ein Helfer (`WindowsPin`) die Wurzel- und Zielverzeichnisse während der gesamten Dateiphase von `apply` und `rollback` als offene
  Handles ohne `FILE_SHARE_DELETE` (ein leeres zusätzlich ohne `FILE_SHARE_WRITE`) fest und prüft über diese Handles vor und nach jedem Schreibvorgang, dass jedes
  Verzeichnis noch ein gewöhnliches Verzeichnis unter seinem endgültigen Pfad ist (`GetFinalPathNameByHandleW`): kein Verzeichnis lässt sich
  zwischen Prüfung und Schreiben wegbenennen und durch eine Junction ersetzen, und ein an Ort und Stelle verändertes bricht die Operation ab;
  ohne laufenden Helfer wird nichts geschrieben; ACLs und `postmaster.pid` werden über das offene
  Handle bzw. mit derselben Wegprüfung gelesen (`client --user` und `check` weisen Wege über Junctions oder symbolische Links ab; verbleibende
  Grenzen im CHANGELOG). Dateien werden über eine Temp-Datei ersetzt (Windows: erst schreiben, dann
  kürzen), nie vorher geleert. Stirbt der Prozess mitten in der Dateiphase (Fehler, Strg+C, kill), spielt ein Wächter die Sicherungen
  zurück — außerhalb von Windows nur mit den PHP-Erweiterungen `pcntl` und `posix`; fehlen sie, ändert `apply` keine Dateien.
- **Neuladen:** ein nicht bestätigtes Neuladen zählt als Fehler (der Anmeldetest würde sonst noch die alte Konfiguration sehen).
- **Grenzen des Anmeldetests:** er prüft die Anmeldung dieses Werkzeugs mit denselben Zugangsdaten — nicht Anwendungen, andere Rollen
  oder Clients ohne TLS. Vor `host` → `hostssl` weist `apply` deshalb ab, wenn gerade Verbindungen anderer Rechner ohne TLS bestehen.
- **SQL:** je Datenbank in einer Transaktion mit `lock_timeout`; nur einzelne einfache `GRANT`-, `REVOKE`- und `ALTER ROUTINE`-Anweisungen in
  genau den Formen, die der Regelkatalog erzeugt (Tabellen nur als Liste von `pg_catalog`-Objekten der Katalog-Sichtbarkeit, nie eine
  Anwendungstabelle), und nur mit Rückweg. Der Rückweg muss die genaue Umkehrung des Fixes sein. Der Server selbst lehnt Mehrfachanweisungen ab
  (`prepare`). Der Rückweg steht im Journal, **bevor** committet wird.
- **Journal** (`--dir`, neues Verzeichnis): `apply-log.json`, `backup/`, `report-before.json`, `report-after.json` und `apply.html`, das
  Protokoll des Laufs für den Browser (Ergebnis, geplante Änderungen, Schritte, Dateien, Vergleich; geschrieben, sobald das Journal angelegt ist, auch wenn der Lauf danach scheitert
  oder abbricht).
  Nach dem Lauf prüft `apply` mit **neuen** Verbindungen erneut und zeigt behoben/neu/offen.
- **`rollback --dir=<Journal>`** spielt die Sicherungen zurück, lädt neu, prüft eine neue Anmeldung und führt die
  gespeicherten Rückweg-Anweisungen aus. Das Journal wird nur angenommen, wenn es dem ausführenden Benutzer gehört und für andere
  unzugänglich ist, zum selben Cluster gehört (Systemkennung, Datenverzeichnis) und nur Pfade nennt, die `apply` auf diesem Server
  schreiben würde. Ein Journal lässt sich nur einmal zurücknehmen. Spätere Änderungen Dritter an denselben Dateien werden dabei überschrieben.
  Ein unvollständiger Rückweg (Fehler oder Abbruch) schreibt kein `rollback-log.json` und lässt sich mit demselben Befehl wiederholen; er spielt
  dann dieselben Sicherungen erneut zurück und führt alle Rückweg-Anweisungen des Journals erneut aus (bereits gelaufene ändern nichts; ein
  zwischenzeitliches `REVOKE` Dritter wird dabei ebenfalls zurückgenommen). Vollständig ist er, wenn er „Rückweg abgeschlossen“ meldet und
  `rollback-log.json` existiert. Jeder Versuch legt neben sein Protokoll eine Fassung für den Browser (`rollback.html` bzw.
  `rollback-attempt-<Zeit>.html`). Während ein Rückweg mit Dateien läuft, unterbrechen ihn Strg+C, Strg+\, `TERM` und `HUP` nicht (wo `pcntl`
  vorhanden ist); andere Signale wie `kill -9` beenden ihn weiterhin — dann denselben Befehl wiederholen. Außerhalb von Windows braucht ein
  Rückweg mit Dateien die PHP-Erweiterungen `pcntl` und `posix`.
- Ohne Terminal verlangt `--execute` zusätzlich `--yes`; ein zweiter `apply` gleichzeitig auf demselben Server wird abgewiesen.

## Schwache Passwörter (`auth.weak_passwords`)

Die gespeicherten SCRAM-SHA-256- und md5-Werte aus `pg_authid` werden für eine kleine, fest im Programm stehende Liste
nachgerechnet (Rollenname mit Varianten und Jahreszahlen, `postgres`, `password`, `admin` u. ä.). Keine Anmeldeversuche,
keine Last am Server, keine externen Wortlisten oder Wörterbücher (die feste Liste steht im Programm; optional ergänzt eine kleine Betreiberliste, siehe unten). Ausgegeben wird nur die Rolle — nie das Passwort, nicht einmal, welcher
Kandidat passte. Superuser nötig.

**Eigene Begriffe:** `--extra-candidates=DATEI` ergänzt die feste Liste um Begriffe des Betriebs (Firmenname, Produkte, Ort, Hausstandard).
Bewusst begrenzt, damit es eine Prüfliste bleibt und kein Wörterbuch wird: höchstens 100 Einträge (einer je Zeile), je höchstens 64 Zeichen, nur ASCII; mehr
bricht den Lauf ab. Die Begriffe werden genau so geprüft, wie sie dastehen (keine automatischen Varianten). Die Datei muss dem ausführenden
Benutzer gehören und für andere unzugänglich sein (Unix: `chmod 600`; Windows: Besitzer sind Sie oder die Administratoren, und die ACL nennt nur Sie, SYSTEM und Administratoren). Sie wird nie
über die Kommandozeile oder stdin übergeben. Der Bericht nennt nur, *wie viele* Begriffe geprüft wurden — weder Inhalt noch Treffer. Zeilen mit Leerzeichen am Anfang oder Ende werden abgewiesen (meist ein Versehen).
Nur betriebsspezifische Begriffe aufnehmen, keine personenbezogenen Daten Dritter (Namen von Beschäftigten oder Angehörigen), und die Datei nach dem Lauf
löschen. Ein Beispiel liegt unter `lab/extra-candidates.example.txt`.

## Katalog-Sichtbarkeit (`db.catalog_visibility`)

Standardmäßig kann jede angemeldete Rolle alle Datenbank- und Rollennamen lesen (`\l`, `\du`, GUI-Werkzeuge) — auch die von
Datenbanken, in die sie sich nicht verbinden darf. `CONNECT` zu entziehen (`db.public_connect`) sperrt den Zugang, versteckt aber
die Namen nicht. Die Regel `db.catalog_visibility` (Stufe `confirm`) entzieht `PUBLIC` das Leserecht auf `pg_database`, `pg_roles`,
`pg_user`, `pg_group`, `pg_auth_members`, `pg_stat_database`, `pg_stat_database_conflicts` und `pg_shdescription`. Der Fix ist ein
einzelnes `REVOKE` je Datenbank mit `GRANT` als Rückweg und läuft über `apply` mit `--include-confirm=db.catalog_visibility`.

Gemessen in PostgreSQL 14 bis 19rc1 (`tests/lab-visibility.sh`, Ergebnis in allen Versionen gleich):

- **Das Recht gehört jeder Datenbank einzeln.** `pg_database` ist ein gemeinsamer Katalog, seine Berechtigung steht aber in der
  `pg_class` jeder Datenbank. Ein `REVOKE` wirkt nur in der Datenbank, in der es läuft. Die Regel prüft deshalb jede Datenbank
  und `template1` (neue Datenbanken erben von dort). `template0` wird nicht geprüft: eine Datenbank, die mit `TEMPLATE template0`
  angelegt wird, trägt den Entzug nicht, erscheint aber beim nächsten `check` als Befund und braucht den Entzug von Hand oder per `apply`.
- **Was danach fehlschlägt** (für alle Rollen ohne eigenes `SELECT`): `\l`, `\du`, Baumansichten und Auswahllisten der
  GUI-Werkzeuge, `pg_dump` als Nicht-Superuser (braucht `pg_database` und `pg_roles`) und alles, was diese Kataloge liest.
  `\d`, `\dt`, `\dn`, `\df` und `\dp` liefen im Test weiter. Anwendungen, die diese Kataloge lesen — Monitoring (etwa ein Exporter
  auf `pg_stat_database`), Treiber mit Metadatenabfragen, Verwaltungswerkzeuge —, brauchen vorher ein gezieltes `SELECT`; das hängt von der
  Anwendung ab und lässt sich hier nicht vorhersagen: in einer Testumgebung erproben. Superuser sind nicht betroffen.
  `pg-harden` selbst braucht für seine Rolle (`pgharden`) dann `GRANT SELECT ON TABLE pg_catalog.pg_database, pg_catalog.pg_roles`
  in jeder Datenbank; ohne dieses Recht auf `pg_database` bricht `check` mit einer entsprechenden Meldung ab (Exit-Code 2), ohne das
  Recht auf `pg_roles` scheitern einzelne Regeln.
- **Der Entzug steht im Dump und überstand die Tests.** `pg_dump` führt ihn als `REVOKE … ON TABLE pg_catalog.…` mit. Gemessen
  (`tests/lab-upgrade.sh`): nach `pg_upgrade` von 17 auf 18 und von 14 auf 19rc1 sowie nach Wiederherstellung eines `pg_dumpall` fehlt `PUBLIC`
  das Leserecht in `template1` und in allen Datenbanken; eine neue Datenbank aus `template1` erbt den Entzug. Nach jedem Upgrade
  oder jeder Wiederherstellung trotzdem `check` fahren.
- **Rückweg:** `rollback` gibt `PUBLIC` das Leserecht zurück (gemessen: der Zugriff funktioniert wieder und der gespeicherte Rechtetext
  trägt wieder `=r/postgres`). Er betrifft nur die Datenbanken, die beim Fix geprüft wurden — Datenbanken, die danach aus `template1`
  entstanden, erben den Entzug und brauchen das `GRANT` selbst. Wer einem Objekt das Recht inzwischen bewusst entzogen hat, bekommt es durch
  den Rückweg ebenfalls zurück.
- **Grenzen — das ist keine Geheimhaltung.** Rollennamen lassen sich weiter über ihre Kennung ermitteln
  (`SELECT g::oid::regrole FROM generate_series(1, 70000) g`), und die Fehlermeldung beim Verbindungsversuch unterscheidet
  `permission denied for database` von `database … does not exist` — damit ist erkennbar, ob eine Datenbank existiert. Die Liste der
  acht Objekte ist nicht erschöpfend: `pg_stat_activity` zeigt weiter Datenbank- und Rollennamen laufender Sitzungen (gemessen: eine
  Sitzung von `rb` in `db_b` war für `ra` sichtbar); Replikationssichten und Tablespaces wurden nicht untersucht. Eine echte Zeilenfilterung gibt es im Katalog nicht: Row-Level-Security auf Systemkatalogen
  weist PostgreSQL ab (gemessen in 18). Wer Mandanten wirklich trennen muss, betreibt **getrennte Cluster** je Mandant.
- **Systemviews umschreiben** (`CREATE OR REPLACE VIEW pg_catalog.pg_roles …`) ging in 18 ohne `allow_system_table_mods`, ist aber ein
  Eingriff in `pg_catalog`, den kein Dump mitführt (Systemviews entstehen mit `initdb` neu); `pg_database` selbst ist
  eine Tabelle und lässt sich so nicht filtern. pg-harden bietet das nicht an.

**Gefilterte Sicht für Anwender** (manuell, als Superuser in jeder Datenbank, in der sie gebraucht wird — pg-harden legt keine
Objekte an; der Eigentümer braucht `SELECT` auf `pg_database`). Die Ansicht läuft mit den Rechten ihres Eigentümers,
`has_database_privilege` wertet aber den aufrufenden Benutzer aus. **`security_barrier` ist nötig:** ohne es konnte in der Probe (PostgreSQL 18)
eine Funktion, die ein Anwender in `WHERE` einsetzte, vor dem Filter der Ansicht laufen und die Namen aller Datenbanken sehen;
mit `security_barrier` sah sie nur die erlaubten.

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

## Betriebssystem-Regeln (Kategorie „Betriebssystem“, `check`)

Nur wenn pg-harden auf dem Server läuft. Der Bericht sagt in der Kopfzeile, ob die Regeln geprüft wurden oder warum nicht
(Server entfernt oder im Container; `postmaster.pid` nicht lesbar). Geprüft werden Rechte von Datenverzeichnis, benutzerdefinierten Tablespaces,
Konfigurations- (einschließlich per `include`/`include_dir` eingebundener Dateien) und Protokolldateien, TLS-Schlüssel, Ablaufdatum von Server- und CA-Zertifikat sowie Socket (Linux: Modi; Windows: ACL über das offene Handle gegen Jeder/Benutzer/
Authentifizierte Benutzer), Dienstkonto, Dienstdatei bzw. Windows-Dienst-Registry (auch unquotierter `ImagePath` und Dienst-ACL) und Prozessumgebung auf Klartext-Geheimnisse (nur Fundstelle und Name),
umask, Log-Verzeichnis auf eigenem Datenträger, freier Platz, Paketherkunft (Linux) bzw. Signatur (Windows).

## `client` — der Rechner, von dem aus verbunden wird

Keine Datenbankverbindung (`client -f NAME` vergleicht mit einem früheren Client-Bericht). Geprüft werden für das aktuelle oder (mit `--user`, Administrator/root nötig) ein anderes Konto:
`pg_service.conf` mit `password=`, Passwortdatei (Windows-ACL, Lage in Cloud-Ordnern, auf Netzfreigaben oder in
Roaming-Profilen, Superuser-Einträge mit Platzhalter-Host, verdeckte Zeilen, fehlende Loopback-Einträge; unter Unix nur als
Hinweis, weil libpq die Datei bei offenen Rechten ohnehin ignoriert), `psql`-Befehlshistorie (`psql_history` / `.psql_history` auf Rechte und Klartext-Passwörter), `PGPASSWORD` in Umgebung und Registry, Passwörter in
Profilen, Skripten, Compose- und `.env`-Dateien, Cron, systemd-Dateien und der Windows-Aufgabenplanung, Client-Schlüssel
und -Zertifikate (Rechte, Ablauf). Gefundene Geheimnisse erscheinen nur mit Fundstelle und Zeile.

`--user` durchsucht das gesamte Profil des fremden Kontos, nicht nur PostgreSQL-Dateien. Bei Konten von Beschäftigten braucht das eine
Rechtsgrundlage (je nach Fall § 26 BDSG oder Art. 6 Abs. 1 lit. f DSGVO) und ggf. eine Betriebsvereinbarung; Berichte tragen Kontoname, Rechnername und Pfade. Zusätzlich zum Profil liest
`client` systemweite Orte (`/etc/environment`, `/etc/profile.d`, `/etc/cron.d`, `/etc/systemd/system`, `/usr/local/bin`) — auch bei `--user`.

Die Suche im Profilordner ist begrenzt (Tiefe 4, 20 000 Einträge, 25 s; Punkt-Ordner, Cloud-Ordner und reine Datenordner werden
ausgelassen — Dateien in Cloud-Ordnern würden beim Lesen heruntergeladen). Weitere Verzeichnisse mit `--scan=a,b`.

## Berichte enthalten Rollen-, Objekt- und Netznamen

Rollennamen sind oft Personenkennungen, `pg_hba`-Zeilen enthalten Netze. Berichte (`-o`), Plan- und Journal-Verzeichnisse werden mit
Dateirechten nur für das ausführende Konto (unter Windows zusätzlich `SYSTEM` und `Administratoren` per `icacls`) geschrieben. Vertraulich
ablegen, vor einer Weitergabe an Dritte prüfen, Aufbewahrung festlegen.

## Regeln und Zuordnungen

- `rules/*.json` — Regeln als Daten: Prüfung per Parameter (`setting`), SQL (`query`, je Befund eine Zeile) oder
  eingebauter Prüfung (`weak_passwords`, `os`, `client`), Version, benötigte Rechte (`requires`), Plattform, Befehl
  (`check`/`client`), Korrektur (`conf`, `sql`, `hba`, `manual`) und Rückweg, Begründung
- `mappings/*.json` — Zuordnung zu BSI IT-Grundschutz Baustein `APP.4.3 Relationale Datenbanken` (Edition 2023, Kennungen und Titel gegen das
  BSI-Original-PDF geprüft) sowie vorläufige Zuordnungen zu ISO/IEC 27001:2022 Annex A und CIS PostgreSQL Benchmark (eigene Gliederung entlang der Abschnitte
  1–7, keine CIS-Kennungen; die Kennungen von ISO und CIS sind noch ungeprüft). Nur Kennungen
  und eigene Kurztitel, kein Norm- oder Benchmark-Text; eine Zuordnung sagt, welche Regeln eine Anforderung berühren, nicht, dass sie erfüllt
  ist. CIS Benchmarks ist eine Marke des Center for Internet Security; pg-harden steht in keiner Verbindung zu CIS und ist von CIS weder
  empfohlen noch zertifiziert

Das Werkzeug liefert technische Prüfergebnisse, die in einem Audit als Beleg herangezogen werden können. Die
Zuordnung zeigt nur das Ergebnis der jeweils zugeordneten Regeln — keine Aussage, ob eine Anforderung der Norm
erfüllt ist; organisatorische Anteile prüft es nicht.

## Testinstanz

`lab/` startet ein PostgreSQL 18 mit absichtlich schwacher Konfiguration und Angriffsfällen für das Werkzeug
selbst (nur an 127.0.0.1 gebunden; Docker 28 oder neuer). Die Rollen `weak_*` und `analyst` haben absichtlich
naheliegende Passwörter für die Passwortprüfung:

```bash
docker compose -f lab/docker-compose.yml up -d
php pg-harden.php check --host=127.0.0.1 --port=55432 --user=postgres
docker compose -f lab/docker-compose.yml down -v
```

Betriebssystem-Regeln, `apply` und `rollback` brauchen Zugriff auf die Dateien des Servers. Das Lab-Programm läuft im
Container; um sie dort zu üben, PHP im Container installieren (`apk add php84 php84-pdo_pgsql php84-mbstring php84-posix`),
das Verzeichnis hineinkopieren und als root im Container ausführen. Übungen nur gegen `lab/` — nie gegen Produktivsysteme.

## Tests

`tests/` enthält: `allowlist-test.php` (Unit-Test der Allowlist, die `apply` und `rollback` passieren müssen; `php tests/allowlist-test.php`),
`catalog-test.php` (Offline-Test für Regelkatalog, Norm-Zuordnungen und `Verifier`), `options-test.php` (Offline-Test der
Kommandozeile, lange Namen und Kurzformen wie bei psql), `windows-redirect.php` und `windows-admin-test.ps1`
(Windows-Wegprüfung, Handle-ACLs und Verzeichnissperre `WindowsPin` gegen Junctions; der zweite läuft mit einem temporären lokalen Konto
ohne Administratorrechte in einer Administrator-PowerShell),
`lab-matrix.sh` (Regressionslauf von `apply`/`rollback` im Container, ruft `lab-identity.php` für die Identitätsregeln beim Schreiben und Lesen als
root auf), `lab-visibility.sh` und `lab-upgrade.sh` (Katalog-Sichtbarkeit,
`pg_upgrade`, Wiederherstellung) und `run-version-matrix.sh` mit `matrix-table.php` (Versionsmatrix, Ergebnis in `VERSIONSMATRIX.md`).
Die Container-Skripte ändern Passwörter, Rollen und Datenbanken und starten nur mit `PGHARDEN_LAB=1` — **ausschließlich in einem
Wegwerf-Container ausführen**, nie gegen eine Instanz mit echten Daten.

## Stand

0.4.0 (unveröffentlicht): **Kommandozeile neu geschnitten** — `-o NAME` schreibt JSON und HTML, `-f NAME` vergleicht mit einem früheren
Bericht, Platzhalter wie `log_filename` für das Datum; `--format`, `--out`, `--previous` und der Befehl `verify` entfallen
(`verify` ist jetzt `check -f`). Windows-Schreibseite hält die Serververzeichnisse gegen einen Tausch gegen Junctions fest über offene Verzeichnis-Handles ohne `FILE_SHARE_DELETE` (`WindowsPin`), ACL-Lesen über das
offene Datei-Handle (`GetSecurityInfo`/`GetFinalPathNameByHandleW`), enge ACLs für Journale und Ausgabedateien unter Windows (beim Laden eines Journals geprüft), Vergleich auch für
Client-Berichte, Regelkatalog auf 86 Regeln erweitert (74 für `check`, 12 für `client`), Zuordnungen zu BSI IT-Grundschutz `APP.4.3`
(Kennungen gegen das BSI-Original geprüft) und, vorläufig, zum CIS PostgreSQL Benchmark ergänzt. Einzelheiten in [CHANGELOG.md](CHANGELOG.md) (englisch).

0.3.2 (26.10.2026): **Sicherheitskorrektur** für `check` und `client` als root (ein anderes Konto konnte sie über einen Link eine Datei
von root lesen lassen, die Prozessprüfungen über `postmaster.pid` auf einen fremden Prozess lenken oder `check` mit einer FIFO anhalten);
Dateien anderer Konten werden jetzt mit deren Identität gelesen. Einzelheiten in [CHANGELOG.md](CHANGELOG.md) (englisch).

0.3.1 (25.10.2026): **Sicherheitskorrektur** für `apply`/`rollback` als root (das Dienstkonto konnte einen Schreibvorgang in ein Verzeichnis
von root umlenken und so root-Rechte erlangen; nach dem Update prüfen wie im [CHANGELOG.md](CHANGELOG.md) beschrieben),
Korrektur für `rollback` in einer Pipe, die vorzeitig schließt (z. B. `| head`), wiederholbarer Rückweg nach einem Abbruch, gegliederte
Berichte, Beispielausgaben unter [examples/](examples/). Einzelheiten in [CHANGELOG.md](CHANGELOG.md) (englisch).

0.3.0 (24.10.2026): `check`, `plan`, `verify`, `client`, `apply`, `rollback`, `rules`; 72 Regeln (61 für `check`, 11 für `client`).
Neu gegenüber 0.2.0: Passwortprüfung ohne Anmeldeversuch, Betriebssystem-Regeln Linux und Windows, `client`, `apply`/`rollback`
mit Schutz vor dem Aussperren, `hba`-Korrekturen, Regel `db.catalog_visibility` (Katalog-Sichtbarkeit). Getestet mit PostgreSQL 14 bis 18
und 19rc1 (`tests/VERSIONSMATRIX.md`); PostgreSQL 19 ist noch ein Release Candidate. Geplant: Rechte Soll/Ist gegen eine Soll-Datei, manuelle Bestätigungen und
Belegpaket mit Hash, Pseudonymisierung von Berichten, BSI-Kennungen, OSCAL, englische Texte.

## Lizenz

MIT-Lizenz, Copyright (c) 2026 Frank Glück (Glück IT) — siehe [LICENSE](LICENSE). Gilt für Code, Regelkatalog und
Zuordnungen; sie enthalten eigene Texte, die Kennungen der Normen und eigene Kurztitel in Anlehnung daran, aber
keine Norm- oder CIS-Texte. Zwingende gesetzliche Haftung (insbesondere für Vorsatz, Arglist, die Verletzung von Leben, Körper und Gesundheit sowie nach dem Produkthaftungsgesetz) bleibt unberührt.

## Verwandte Projekte und Schulungen

- **[Produktseite pg-harden](https://dozent.net/produkte/pg-harden)** — Überblick mit Beispielausgaben.
- **[pg-clusterbackup](https://github.com/glueck-it/pg-clusterbackup)** — sichert jede Datenbank jedes laufenden PostgreSQL-Clusters in einem
  zeitgesteuerten Job (PHP, Bash, PowerShell).
- **[PostgreSQL Konfigurator](https://dozent.net/produkte/postgresql-konfigurator)** — Webwerkzeug für hardwareangepasste `postgresql.conf`-Konfigurationen.
- **[Seminar: PostgreSQL Security und Härtung](https://dozent.net/seminare/postgresql/postgresql-security-haertung)** (Schulung) — der fachliche Hintergrund
  zu den Regeln dieses Werkzeugs.

## Über den Autor

Entwickelt und gepflegt von **Frank Glück** ([Glück IT](https://dozent.net)) — Berater, Entwickler und Dozent für Datenbanken und
Programmiersprachen. Ein großer Teil der Projektarbeit sind Migrationen nach PostgreSQL, etwa von
[Oracle](https://dozent.net/seminare/postgresql/migration/migration-von-oracle-zu-postgresql),
[SQL Server](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-sql-server),
[DB2](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-db2),
[Informix](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-informix),
[Sybase](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-sybase) oder
[MS Access](https://dozent.net/seminare/postgresql/migration/postgresql-migration-von-ms-access).

- Hilfe bei PostgreSQL, einer Sicherheitsprüfung, einer Migration oder der Sicherungsstrategie? [Kontakt](https://dozent.net).
- Seminare zu [PostgreSQL-Administration](https://dozent.net/seminare/postgresql/postgresql-administration),
  [Performance Tuning](https://dozent.net/seminare/postgresql/postgresql-performance-tuning),
  [PL/pgSQL](https://dozent.net/seminare/postgresql/plpgsql-programmierung), SQL Server (T-SQL/SSRS/SSAS),
  [PHP](https://dozent.net/seminare/programmieren/php), JS und weiteren Webtechnologien.
- Außerdem entsteht [Inside Filings](https://inside-filings.com/news) — auffällige Insider-, Kongress-/Weißes-Haus- und 13F-Bewegungen aus SEC-Meldungen und weiteren amtlichen Veröffentlichungen.
