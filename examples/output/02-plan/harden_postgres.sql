-- pg-harden 0.4.0 — für Datenbank postgres, erzeugt 2026-10-29 13:50
-- Automatisch erzeugter Vorschlag. Auswirkungen auf Anwendungen vor dem Ausführen in einer Testumgebung prüfen.
-- Ohne Gewähr (MIT-Lizenz). Prüfergebnisse und Pläne sind Vorschläge: Befunde fachlich bewerten, jede Änderung selbst prüfen und vor dem Einsatz in Produktion testen. Ein Lauf ohne Befund heißt nur, dass die Regeln des Katalogs nichts gefunden haben — nicht, dass die Instanz sicher ist.
-- Ausführen: Verbindung zur Zieldatenbank selbst herstellen, dann mit -v ON_ERROR_STOP=1 -f harden_postgres.sql einspielen.
-- Die Datei bricht ab, wenn sie in einer anderen Datenbank läuft (Division durch null in der ersten Anweisung).
-- Zeilen mit "-- BESTÄTIGEN:" sind auskommentiert: Auswirkung prüfen, dann freischalten.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL standard_conforming_strings = on;
SELECT 1 / (pg_catalog.current_database() = 'postgres')::int AS richtige_datenbank;

-- db.public_temp: postgres
-- BESTÄTIGEN: REVOKE TEMPORARY ON DATABASE postgres FROM PUBLIC;
-- Rückweg: GRANT TEMPORARY ON DATABASE postgres TO PUBLIC;

-- db.public_connect: postgres
-- BESTÄTIGEN: REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
-- Rückweg: GRANT CONNECT ON DATABASE postgres TO PUBLIC;

-- db.public_connect: shop
-- BESTÄTIGEN: REVOKE CONNECT ON DATABASE shop FROM PUBLIC;
-- Rückweg: GRANT CONNECT ON DATABASE shop TO PUBLIC;

-- db.catalog_visibility: postgres
-- BESTÄTIGEN: REVOKE SELECT ON TABLE pg_catalog.pg_auth_members, pg_catalog.pg_database, pg_catalog.pg_group, pg_catalog.pg_roles, pg_catalog.pg_shdescription, pg_catalog.pg_stat_database, pg_catalog.pg_stat_database_conflicts, pg_catalog.pg_user FROM PUBLIC;
-- Rückweg: GRANT SELECT ON TABLE pg_catalog.pg_auth_members, pg_catalog.pg_database, pg_catalog.pg_group, pg_catalog.pg_roles, pg_catalog.pg_shdescription, pg_catalog.pg_stat_database, pg_catalog.pg_stat_database_conflicts, pg_catalog.pg_user TO PUBLIC;

COMMIT;
