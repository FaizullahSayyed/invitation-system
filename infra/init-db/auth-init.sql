-- infra/init-db/auth-init.sql
-- Run as superuser to create the service user

-- Revoke all default privileges
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Create dedicated service user with minimal privileges
CREATE USER auth_svc_user WITH PASSWORD 'CHANGE_ME_SECURE_PASSWORD';
ALTER USER auth_svc_user SET default_transaction_read_only = false;

-- Grant connect only
GRANT CONNECT ON DATABASE auth_db TO auth_svc_user;

-- Grant usage on schema
GRANT USAGE ON SCHEMA public TO auth_svc_user;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index on email for login lookups
CREATE INDEX idx_users_email ON users(email);

-- Grant table-level permissions (NO DROP, NO ALTER)
GRANT SELECT, INSERT, UPDATE ON users TO auth_svc_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO auth_svc_user;

-- Prevent service user from creating/dropping tables
REVOKE CREATE ON SCHEMA public FROM auth_svc_user;