ALTER TABLE package_versions
    ADD COLUMN signature_kind text,
    ADD COLUMN signature_key_id text,
    ADD COLUMN signature_bytes bytea;

