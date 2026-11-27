-- Optional, irreversible opt-in to secure issuance. Only the offline schema
-- owner can configure or rotate the active signing public key and scope.
CREATE TABLE chezhi_signing_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    deployment text NOT NULL CHECK (deployment ~ '^[0-9a-f]{64}$'),
    public_key text NOT NULL CHECK (public_key ~ '^[0-9a-f]{64}$')
);
