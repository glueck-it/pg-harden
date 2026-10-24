-- Beispiel-Szenario für examples/: eine über Jahre gewachsene Installation einer Shop-Anwendung.
-- ACHTUNG: absichtlich schwache, öffentlich bekannte Zugangsdaten — nur für einen Wegwerf-Container.
-- Die trust-Zeilen in pg_hba.conf kommen aus POSTGRES_HOST_AUTH_METHOD=trust (generate.sh).

-- Altlast md5: das Passwort wurde gesetzt, als md5 noch Standard war
SET password_encryption = 'md5';
CREATE ROLE reporting LOGIN PASSWORD 'reporting2019';
RESET password_encryption;

-- Anwendung mit schwachem Passwort (Rollenname + Jahreszahl)
CREATE ROLE shop_app LOGIN PASSWORD 'shop_app2024';
-- Wartungsrolle mit starkem Passwort (durch die Veröffentlichung trotzdem verbrannt), aber Row-Level-Security-Ausnahme
CREATE ROLE support LOGIN BYPASSRLS PASSWORD 'k8#Qw2!vL0pZr9';

CREATE DATABASE shop OWNER shop_app;
\connect shop
-- Altbestand aus einer Version vor 15: jeder darf im Schema public anlegen
GRANT CREATE ON SCHEMA public TO PUBLIC;
CREATE TABLE public.orders (id bigint PRIMARY KEY, customer text, total numeric(10,2));
-- Funktion mit den Rechten des Eigentümers, ohne festen search_path
CREATE FUNCTION public.order_total(p_id bigint) RETURNS numeric
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT total FROM orders WHERE id = p_id $$;
