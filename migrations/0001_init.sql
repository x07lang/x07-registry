CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    handle text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    label text NOT NULL DEFAULT '',
    scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);

CREATE INDEX tokens_user_id_created_at_idx ON tokens(user_id, created_at DESC);

CREATE TABLE packages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid NOT NULL REFERENCES users(id),
    latest_version text
);

CREATE TABLE package_owners (
    package_id uuid NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (package_id, user_id)
);

CREATE TABLE package_versions (
    package_id uuid NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version text NOT NULL,
    cksum text NOT NULL,
    yanked boolean NOT NULL DEFAULT false,
    manifest jsonb NOT NULL,
    published_at timestamptz NOT NULL DEFAULT now(),
    published_by uuid NOT NULL REFERENCES users(id),
    PRIMARY KEY (package_id, version)
);

CREATE INDEX package_versions_package_id_published_at_idx
    ON package_versions(package_id, published_at DESC);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now(),
    actor_user_id uuid REFERENCES users(id),
    actor_token_id uuid REFERENCES tokens(id),
    action text NOT NULL,
    package_name text,
    package_version text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_events_actor_user_id_created_at_idx
    ON audit_events(actor_user_id, created_at DESC);
