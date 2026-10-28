-- ACHTUNG: Übungsdaten. Alle Zugangsdaten in dieser Datei sind absichtlich schwach bzw. öffentlich bekannt und
-- dürfen nirgends produktiv verwendet werden.
-- Typische Schwachstellen einer über Jahre gewachsenen Installation.
-- Läuft nur beim ersten Start des Lab-Containers (docker-entrypoint-initdb.d).
-- Die trust-Zeilen in pg_hba.conf kommen nicht von hier, sondern aus
-- POSTGRES_HOST_AUTH_METHOD=trust in docker-compose.yml.

-- Altlast MD5: Passwort wurde gesetzt, als md5 noch Standard war
SET password_encryption = 'md5';
CREATE ROLE legacy_report LOGIN PASSWORD 'report2014';
RESET password_encryption;

-- Anwendung läuft als Superuser
CREATE ROLE shop_app LOGIN SUPERUSER PASSWORD 'shop';

-- Import-Rolle mit Zugriff auf Serverdateien, direkt und über eine Gruppe
CREATE ROLE etl_import LOGIN PASSWORD 'etl';
GRANT pg_read_server_files TO etl_import;
CREATE ROLE data_team NOLOGIN;
GRANT pg_execute_server_program TO data_team;
CREATE ROLE analyst LOGIN PASSWORD 'analyst' IN ROLE data_team;

-- Wartungsrolle, die Row-Level Security umgeht, und Benutzerverwaltung mit CREATEROLE
CREATE ROLE support_team LOGIN BYPASSRLS PASSWORD 'support';
CREATE ROLE user_admin LOGIN CREATEROLE PASSWORD 'user_admin_123';

-- Verwaister Replikations-Slot eines abgebauten Standbys
SELECT pg_create_physical_replication_slot('old_standby', true);

-- Rolle schwächt sich selbst ab (ALTER ROLE … SET)
ALTER ROLE legacy_report SET password_encryption = 'md5';
ALTER ROLE legacy_report SET log_statement = 'none';

-- Angriffsfälle für das Werkzeug selbst (müssen abgewiesen bzw. entschärft werden):
-- Datenbanknamen, die libpq/psql als Verbindungsparameter lesen könnten
CREATE DATABASE "x host=127.0.0.9 port=1";
CREATE DATABASE "postgresql://10.255.255.2:5432/shop";
-- Namen, die sich nur in der Schreibweise unterscheiden (Plan-Dateien auf Windows/macOS)
CREATE DATABASE "Shop";
-- Rollenname mit Markdown (Zählpixel in MANUELL.md)
CREATE ROLE "![x](https://example.invalid/leak.png)" LOGIN BYPASSRLS;
-- Datenbank, zu der keine Verbindung erlaubt ist (darf nicht still herausfallen)
CREATE DATABASE closed_db;
ALTER DATABASE closed_db ALLOW_CONNECTIONS false;

-- Datenbank wie nach einem Upgrade von Version 14: public für alle beschreibbar
CREATE DATABASE shop;
\connect shop
GRANT CREATE ON SCHEMA public TO PUBLIC;

CREATE TABLE public.customer (id bigint PRIMARY KEY, name text, iban text);

-- Tabelle mit aktivierter Row-Level Security, aber vergessener Policy (sperrt Nicht-Eigentümer still aus)
CREATE TABLE public.invoice (id bigint PRIMARY KEY, customer_id bigint, amount numeric(12,2));
ALTER TABLE public.invoice ENABLE ROW LEVEL SECURITY;

-- Standard-Privilegien für künftige Tabellen an PUBLIC vergeben
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;

-- SECURITY DEFINER ohne festen search_path
CREATE FUNCTION public.customer_count() RETURNS bigint
  LANGUAGE sql SECURITY DEFINER
  AS 'SELECT count(*) FROM customer';

-- SECURITY DEFINER mit search_path, aber ohne pg_temp am Ende
CREATE FUNCTION public.customer_name(bigint) RETURNS text
  LANGUAGE sql SECURITY DEFINER SET search_path = public
  AS 'SELECT name FROM customer WHERE id = $1';

-- Funktion in eigenem Schema, die auf public angewiesen ist: der Plan darf public nicht entfernen
CREATE SCHEMA billing;
CREATE FUNCTION billing.charge() RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = public
  AS 'SELECT count(*) FROM customer';

-- Funktionsname mit Zeilenumbruch und psql-Metabefehl: darf nie in eine SQL-Datei gelangen
CREATE FUNCTION public."evil
\! echo PWNED #"() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';

-- Funktionsname mit Bidi-Steuerzeichen U+202E (Trojan Source): darf nicht unsichtbar in den Plan
CREATE FUNCTION public.U&"rlo\202Egnp.exe"() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';

\connect 'Shop'
GRANT CREATE ON SCHEMA public TO PUBLIC;

-- Schwache Passwörter für die Prüfung auth.weak_passwords (SCRAM und md5; Rollenname, Rollenname mit Jahr, Standardwert)
CREATE ROLE weak_same LOGIN PASSWORD 'weak_same';
CREATE ROLE weak_year LOGIN PASSWORD 'weak_year2025';
CREATE ROLE weak_admin LOGIN PASSWORD 'admin';
SET password_encryption = 'md5';
CREATE ROLE weak_md5 LOGIN PASSWORD 'Weak_md52024';
RESET password_encryption;
CREATE ROLE strong_one LOGIN PASSWORD 'lab-only-Strong-Password-1';

-- Passwort mit Firmenbezug: nur über --extra-candidates auffindbar
CREATE ROLE weak_custom LOGIN PASSWORD 'Nordwind-Lab-7';
