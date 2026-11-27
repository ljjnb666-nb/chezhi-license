-- Short-lived proof challenges; no plaintext card keys or private keys.
CREATE TABLE chezhi_challenges (
    nonce text PRIMARY KEY CHECK (nonce ~ '^[0-9a-f]{64}$'),
    payload bytea NOT NULL CHECK (octet_length(payload) <= 4096),
    expires bigint NOT NULL CHECK (expires > 0)
);
CREATE INDEX chezhi_challenges_expiry_idx ON chezhi_challenges(expires);
