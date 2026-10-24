# Manuelle Maßnahmen

Erzeugt von pg-harden 0.3.0 am 24.10.2026 21:06.

Automatisch erzeugter Vorschlag. Auswirkungen auf Anwendungen vor dem Ausführen in einer Testumgebung prüfen. Der Plan enthält Rollen-, Objekt- und Netznamen: vertraulich ablegen.

Ohne Gewähr (MIT-Lizenz). Prüfergebnisse und Pläne sind Vorschläge: Befunde fachlich bewerten, jede Änderung selbst prüfen und vor dem Einsatz in Produktion testen. Ein Lauf ohne Befund heißt nur, dass die Regeln des Katalogs nichts gefunden haben — nicht, dass die Instanz sicher ist.

## Nicht vollständig geprüft

- Dienstdatei und Prozessumgebung enthalten keine Klartext-Geheimnisse (os.service_unit): ` nicht geprüft: Umgebung des Serverprozesses nicht lesbar (/proc/1/environ — root bzw. Dienstkonto nötig); Kein systemd-Dienst ermittelt — Dienstdatei nicht geprüft `
- Serverprogramm stammt aus der Paketverwaltung (Linux) bzw. ist unverändert (Windows) (os.package_source): ` nicht geprüft: Programmdatei des Serverprozesses nicht ermittelbar (/proc/1/exe — root nötig) `

## TLS ist eingeschaltet (tls.ssl_enabled, hoch)

Ohne TLS gehen Abfragen, Ergebnisse und bei schwachen Verfahren auch Anmeldedaten im Klartext über das Netz.

**Maßnahme:** Zertifikat und Schlüssel bereitstellen (ssl_cert_file, ssl_key_file), ssl = on, Konfiguration neu laden.

- ` ssl: ist 'off', erwartet 'on' `

## Netzwerkzugänge in pg_hba.conf verlangen TLS (hba.host_without_tls, mittel)

Eine host-Zeile erlaubt auch unverschlüsselte Verbindungen. Ob TLS genutzt wird, entscheidet dann der Client.

**Maßnahme:** host durch hostssl ersetzen; als letzte Zeile 'hostnossl all all all reject' ergänzen.

Mit `apply` ausführbar (Rückweg und Schutz vor dem Aussperren inklusive): `--include-confirm=hba.host_without_tls`.

- ` Zeile 130: host all all all trust `

## Keine Rolle hat noch ein MD5-Passwort (auth.md5_passwords, hoch)

Ein vorhandener MD5-Hash bleibt bestehen, bis das Passwort neu gesetzt wird.

**Maßnahme:** Passwort je Rolle neu setzen (psql: \password <rolle>), nachdem password_encryption auf scram-sha-256 steht.

- ` reporting: Passwort als MD5-Hash gespeichert `

## Kein Passwort einer anmeldefähigen Rolle stammt aus der Prüfliste (naheliegende Werte, optional Betreiberbegriffe) (auth.weak_passwords, hoch)

Die gespeicherten SCRAM- und MD5-Werte aus pg_authid werden für eine kleine, fest umrissene Liste naheliegender Kandidaten (Rollenname, postgres, password, admin, Rollenname mit Jahreszahl u. ä.) nachgerechnet, auf Wunsch ergänzt um eine vom Betreiber bereitgestellte Liste betriebsspezifischer Begriffe (höchstens 100 Einträge, --extra-candidates). Es gibt keine Anmeldeversuche und keine Last am Server; ausgegeben wird nur die Rolle, nie das Passwort. Ein Lauf ohne Befund heißt nicht, dass die Passwörter stark sind — nur, dass sie nicht in dieser kurzen Liste stehen.

**Maßnahme:** Passwort der Rolle neu setzen (psql: \password <rolle>) und für Anwendungen ein langes, zufälliges Geheimnis verwenden. passwordcheck bzw. credcheck verhindert triviale Passwörter künftig (Regel auth.password_policy).

- ` reporting: Passwort stammt aus der Prüfliste (wird nicht ausgegeben) `
- ` shop_app: Passwort stammt aus der Prüfliste (wird nicht ausgegeben) `

## Kein Netzwerkzugang für alle Adressen (hba.open_to_all, hoch)

Ein Eintrag für alle Adressen öffnet die Anmeldung für jedes Netz, das den Port erreicht.

**Maßnahme:** Auf die tatsächlichen Netze der Anwendungsserver und Administratoren einschränken.

- ` Zeile 130: host all all all trust `

## Keine Anmeldung ohne Passwort (trust) (hba.trust, hoch)

trust lässt jeden, der die Verbindung herstellen kann, ohne Passwort als jede in der Zeile zugelassene Rolle ein — bei 'all' auch als Superuser.

**Maßnahme:** Lokal peer (Linux) bzw. scram-sha-256 verwenden. Vor dem Neuladen sicherstellen, dass ein Zugang erhalten bleibt.

Mit `apply` ausführbar (Rückweg und Schutz vor dem Aussperren inklusive): `--include-confirm=hba.trust`.

- ` Zeile 117: local all all  `
- ` Zeile 119: host all all 127.0.0.1 `
- ` Zeile 121: host all all ::1 `
- ` Zeile 124: local replication all  `
- ` Zeile 125: host replication all 127.0.0.1 `
- ` Zeile 126: host replication all ::1 `
- ` Zeile 130: host all all all `

## Superuser können sich nicht über das Netz anmelden (hba.superuser_remote, mittel)

Ein über das Netz erreichbarer Superuser macht aus einem gestohlenen Passwort die volle Kontrolle über Server und Betriebssystemkonto. Gruppen (+rolle) werden aufgelöst; eine vorangestellte reject-Zeile für alle Adressen hebt den Befund auf. Prüft eine einzelne pg_hba.conf ohne Include-Reihenfolge.

**Maßnahme:** Superuser nur lokal zulassen; davor eine reject-Zeile für Superuser über das Netz setzen. 'all' durch konkrete Rollen ersetzen.

- ` Zeile 130: host all all — Superuser postgres `

## Bremse nach Fehlanmeldung (auth_delay) geladen (auth.auth_delay, niedrig)

Ohne Verzögerung lassen sich Passwörter in hoher Frequenz durchprobieren.

**Maßnahme:** auth_delay in shared_preload_libraries aufnehmen, auth_delay.milliseconds setzen (Neustart erforderlich).

- ` auth_delay: auth_delay nicht geladen `

## Passwortrichtlinie aktiv (passwordcheck oder credcheck) (auth.password_policy, niedrig)

Ohne Prüfung akzeptiert PostgreSQL jedes Passwort, auch ein triviales wie den Rollennamen. Geprüft wird nur, ob ein Modul in shared_preload_libraries oder session_preload_libraries geladen ist, nicht seine Einstellungen.

**Maßnahme:** passwordcheck (contrib) oder credcheck laden. Gilt nur für Passwörter, die über SQL gesetzt werden.

- ` shared_preload_libraries: weder passwordcheck noch credcheck geladen `

## Row-Level Security umgehen nur Superuser (roles.bypassrls, mittel)

BYPASSRLS hebelt jede Policy aus; das Recht fällt bei Prüfungen der Policies leicht durch.

**Maßnahme:** BYPASSRLS nur für Sicherungs- oder Wartungsrollen, die es nachweislich brauchen.

- ` support: BYPASSRLS `

## pgAudit ist geladen (log.pgaudit, mittel)

Die Bordmittel protokollieren Anweisungstexte, aber nicht zuverlässig, auf welche Tabellen eine Anweisung tatsächlich zugreift (Views, Funktionen, dynamisches SQL). Das leistet pgAudit mit Session- und Object-Audit.

**Maßnahme:** pgaudit installieren, in shared_preload_libraries aufnehmen (Neustart), pgaudit.log bzw. Objekt-Audit einrichten.

- ` shared_preload_libraries: pgaudit nicht geladen `

## WAL-Archivierung ist eingeschaltet (avail.archive_enabled, mittel)

Ohne WAL-Archiv ist keine Wiederherstellung auf einen Zeitpunkt (PITR) möglich; nach einem Fehler oder Angriff bleibt nur die letzte Vollsicherung.

**Maßnahme:** Archivierung mit einem Sicherungswerkzeug einrichten (pgBackRest, Barman oder archive_command/archive_library); archive_mode = on erfordert einen Neustart. Bewusst ohne Archiv betriebene Instanzen dokumentieren.

- ` archive_mode: ist 'off', erwartet eines von: on, always `

## Temporäre Dateien je Prozess sind begrenzt (avail.temp_file_limit, mittel)

Jede angemeldete Rolle kann mit einer einzigen Abfrage die Platte füllen und damit den Server für alle stoppen.

**Maßnahme:** temp_file_limit passend zur freien Kapazität setzen; gilt je Prozess, nicht in Summe.

- ` temp_file_limit: ist '-1', erwartet nicht '-1' `

## Offen hängende Transaktionen werden beendet (sess.idle_in_transaction, niedrig)

Eine offene, untätige Transaktion hält Sperren und verhindert das Aufräumen durch VACUUM.

**Maßnahme:** idle_in_transaction_session_timeout setzen, z. B. 10min; bei Bedarf je Rolle abweichend.

- ` idle_in_transaction_session_timeout: ist '0', erwartet größer als 0 `

## Datenprüfsummen sind eingeschaltet (data.checksums, mittel)

Ohne Prüfsummen fällt eine stille Beschädigung von Datenseiten erst auf, wenn die Daten schon falsch gelesen wurden.

**Maßnahme:** Neu angelegte Cluster ab Version 18 haben sie standardmäßig; bestehende mit pg_checksums --enable im gestoppten Zustand.

- ` data_checksums: ist 'off', erwartet 'on' `

## Unix-Socket-Verzeichnis ist nicht für alle beschreibbar, Socket nicht für alle erreichbar (os.socket_permissions, niedrig)

In einem für alle beschreibbaren Verzeichnis (z. B. /tmp) kann ein anderer Benutzer einen Socket unterschieben, sobald der Server nicht läuft. unix_socket_permissions = 0777 (Voreinstellung) lässt jeden lokalen Benutzer die Anmeldung versuchen; dann schützt allein pg_hba.conf.

**Maßnahme:** unix_socket_directories auf ein Verzeichnis nur für das Dienstkonto und die Anwendungsgruppe legen (z. B. /var/run/postgresql, 0775 oder 0750); unix_socket_permissions = 0770 mit unix_socket_group.

- ` unix_socket_permissions: ist 0777 — jeder Benutzer des Systems kann den Socket erreichen; die Anmeldung schützt dann allein pg_hba.conf (peer) `
