CREATE INDEX chezhi_cards_order_idx ON chezhi_cards (ref);
CREATE INDEX chezhi_audit_card_idx ON chezhi_audit (card_id) WHERE card_id IS NOT NULL;
