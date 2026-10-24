SET password_encryption = 'scram-sha-256';
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT rolname FROM pg_roles WHERE rolcanlogin LOOP
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r.rolname, 'Test-pw-1');
  END LOOP;
END $$;
ALTER ROLE legacy_report RESET password_encryption;
