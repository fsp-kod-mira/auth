CREATE TYPE roles AS ENUM ('admin', 'recruiter', 'hiring-manager', 'resource-manager');

CREATE TABLE IF NOT EXISTS users
(
    id                TEXT PRIMARY KEY,
    last_name         TEXT NOT NULL,
    first_name        TEXT NOT NULL,
    middle_name       TEXT NOT NULL,
    role              roles           NOT NULL,
    password          TEXT            NOT NULL,
    email             TEXT UNIQUE,
    created_at        TIMESTAMP       NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMP
);
