ALTER TABLE users
    ADD COLUMN created_via text NOT NULL DEFAULT 'bootstrap',
    ADD COLUMN github_user_id bigint,
    ADD COLUMN github_login text,
    ADD COLUMN github_avatar_url text,
    ADD COLUMN github_profile_url text,
    ADD COLUMN github_email text,
    ADD COLUMN github_email_verified boolean NOT NULL DEFAULT false,
    ADD COLUMN github_email_primary boolean NOT NULL DEFAULT false;

ALTER TABLE users
    ADD CONSTRAINT users_created_via_check CHECK (created_via IN ('bootstrap', 'github'));

CREATE UNIQUE INDEX users_github_user_id_uq
    ON users (github_user_id)
    WHERE github_user_id IS NOT NULL;

CREATE TABLE web_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash text NOT NULL UNIQUE,
    csrf_token text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX web_sessions_user_id_idx ON web_sessions(user_id);
CREATE INDEX web_sessions_expires_at_idx ON web_sessions(expires_at);

CREATE TABLE oauth_states (
    state text PRIMARY KEY,
    next_url text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX oauth_states_expires_at_idx ON oauth_states(expires_at);
