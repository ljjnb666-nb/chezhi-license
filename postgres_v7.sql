-- Every change of card authorization state advances its epoch. Runtime
-- writes are made under the card row lock by the shared business layer.
ALTER TABLE chezhi_cards ADD COLUMN auth_epoch bigint NOT NULL DEFAULT 1
    CHECK (auth_epoch > 0);
-- V5/V6 challenge transcripts lack the signed epoch. Never reinterpret them.
DELETE FROM chezhi_challenges;
