CREATE TABLE package_version_advisories (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id uuid NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('broken', 'security', 'deprecated')),
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    summary text NOT NULL,
    details text NOT NULL DEFAULT '',
    url text,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid REFERENCES users(id),
    withdrawn_at timestamptz,
    withdrawn_by uuid REFERENCES users(id),
    FOREIGN KEY (package_id, version) REFERENCES package_versions(package_id, version) ON DELETE CASCADE
);

CREATE INDEX package_version_advisories_package_id_version_idx
    ON package_version_advisories(package_id, version);

CREATE INDEX package_version_advisories_package_id_withdrawn_at_idx
    ON package_version_advisories(package_id, withdrawn_at);
