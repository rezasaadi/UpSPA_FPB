-- TODO(UPSPA-SP): Implement this SQL file.
-- - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
-- - Ensure schema supports setup + records + replay protection (last_pwd_update_time)
CREATE TABLE IF NOT EXISTS setup (
    uid_b64 TEXT PRIMARY KEY,
    sig_pk_b64 TEXT NOT NULL,
    cid_nonce_b64 TEXT NOT NULL,
    cid_ct_b64 TEXT NOT NULL,
    cid_tag_b64 TEXT NOT NULL,
    k_i_b64 TEXT NOT NULL,
    last_pwd_update_time BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS records (
    suid_b64 TEXT PRIMARY KEY,
    cj_nonce_b64 TEXT NOT NULL,
    cj_ct_b64 TEXT NOT NULL,
    cj_tag_b64 TEXT NOT NULL
);
