WITH app_tables AS (
    SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname IN
        ('chezhi_schema','chezhi_config','chezhi_orders','chezhi_cards','chezhi_audit',
         'chezhi_plans','chezhi_members','chezhi_owner','chezhi_import','chezhi_sessions','chezhi_rate_limits','chezhi_deployment','chezhi_challenges','chezhi_secure_bindings')
), manifest AS (
    SELECT 'table/' || t.relname AS key,
        jsonb_build_array(t.relkind, t.relpersistence, t.relrowsecurity)::text AS definition
    FROM app_tables t
    UNION ALL
    SELECT 'column/' || t.relname || '/' || a.attname,
        jsonb_build_array(format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,
            pg_get_expr(d.adbin,d.adrelid))::text
    FROM app_tables t JOIN pg_attribute a ON a.attrelid=t.oid
    LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum
    WHERE a.attnum>0 AND NOT a.attisdropped
    UNION ALL
    SELECT 'constraint/' || t.relname || '/' || c.conname,
        jsonb_build_array(c.convalidated,pg_get_constraintdef(c.oid))::text
    FROM app_tables t JOIN pg_constraint c ON c.conrelid=t.oid
    UNION ALL
    SELECT 'index/' || t.relname || '/' || idx.relname,
        jsonb_build_array(i.indisvalid,i.indisready,i.indislive,pg_get_indexdef(idx.oid))::text
    FROM app_tables t JOIN pg_index i ON i.indrelid=t.oid JOIN pg_class idx ON idx.oid=i.indexrelid
    UNION ALL
    SELECT 'sequence/' || c.relname, jsonb_build_array(c.relpersistence,s.seqtypid::regtype::text,
        s.seqstart,s.seqincrement,s.seqmin,s.seqmax,s.seqcycle)::text
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_sequence s ON s.seqrelid=c.oid
    WHERE n.nspname='public' AND c.relname IN ('chezhi_cards_position_seq','chezhi_audit_position_seq')
    UNION ALL
    SELECT 'domain/' || typ.typname || '/' || c.conname,
        jsonb_build_array(format_type(typ.typbasetype,typ.typtypmod),c.convalidated,pg_get_constraintdef(c.oid))::text
    FROM pg_type typ JOIN pg_namespace n ON n.oid=typ.typnamespace
    JOIN pg_constraint c ON c.contypid=typ.oid
    WHERE n.nspname='public' AND typ.typname='chezhi_instant' AND typ.typtype='d'
)
SELECT jsonb_pretty(jsonb_object_agg(key, definition)) FROM manifest;
