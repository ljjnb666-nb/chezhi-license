-- A record in this table permanently marks a card as requiring device proof.
-- An administrator may clear its current key, but must not remove the marker.
CREATE TABLE chezhi_secure_bindings (
    card_id text PRIMARY KEY REFERENCES chezhi_cards(id),
    public_key text NOT NULL CHECK (public_key = '' OR public_key ~ '^04[0-9a-f]{128}$'),
    revision bigint NOT NULL CHECK (revision > 0)
);
