-- Harmonia Matrix declaration: peer-authenticated local role; no password material.
SELECT 'CREATE ROLE "matrix-synapse" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'matrix-synapse')\gexec
ALTER ROLE "matrix-synapse" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT;
SELECT 'CREATE DATABASE synapse OWNER "matrix-synapse" ENCODING ''UTF8'' LC_COLLATE ''C'' LC_CTYPE ''C'' TEMPLATE template0'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'synapse')\gexec
