ALTER TABLE package_versions
    ADD COLUMN scale_classes_supported text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN scale_tested boolean NOT NULL DEFAULT false,
    ADD COLUMN scale_test_evidence_ref text;

CREATE INDEX package_versions_scale_tested_true_idx
    ON package_versions(scale_tested)
    WHERE scale_tested = true;
