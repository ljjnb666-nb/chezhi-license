"""Capture representative PostgreSQL plans from the benchmark fixture."""
import json
from pathlib import Path

STATUS = """CASE WHEN c.revoked THEN '已吊销'
    WHEN c.expires<={now}::numeric THEN '已过期'
    WHEN c.activated IS NULL THEN '未激活'
    WHEN c.device='' THEN '已解绑' ELSE '已激活' END"""


def capture_plans(sql, folder, label, baseline):
    now, start, end = [int(x) for x in sql("""SELECT
        (62135596800+floor(extract(epoch FROM now())))::bigint,
        (62135596800+extract(epoch FROM (
            date_trunc('day',now() AT TIME ZONE 'Asia/Shanghai')-interval '6 days'
        ) AT TIME ZONE 'Asia/Shanghai'))::bigint,
        (62135596800+extract(epoch FROM (
            date_trunc('day',now() AT TIME ZONE 'Asia/Shanghai')+interval '1 day'
        ) AT TIME ZONE 'Asia/Shanghai'))::bigint""").split("|")]
    status = STATUS.format(now=now)
    order_filter = """WHERE o.channel='wechat'
        AND strpos(lower(o.ref COLLATE "pg_c_utf8"),'http-scale')>0"""
    cards_filter = f"""WHERE ({status})='已激活'
        AND (strpos(lower(c.prefix COLLATE "pg_c_utf8"),'abc')>0
        OR strpos(lower(c.ref COLLATE "pg_c_utf8"),'abc')>0) AND o.channel='wechat'"""
    order_fields = """o.ref,o.channel,o.created,o.days,count(*),
        count(*) FILTER (WHERE c.activated IS NOT NULL),count(*) FILTER (WHERE c.revoked),sum(o.cents)"""
    if baseline:
        queries = {
            "overview-status": f"""SELECT count(*),count(*) FILTER(WHERE state='已激活'),
                count(*) FILTER(WHERE state='未激活'),count(*) FILTER(WHERE state='已过期'),
                count(*) FILTER(WHERE state='已吊销'),count(*) FILTER(WHERE state='已解绑'),
                count(DISTINCT ref) FILTER(WHERE channel<>'test'),coalesce(sum(cents) FILTER(WHERE channel<>'test'),0)
                FROM (SELECT c.ref,o.channel,o.cents,{status} AS state
                    FROM chezhi_cards c JOIN chezhi_orders o USING(ref)) s""",
            "overview-sales": f"""SELECT floor((o.created-{start}::numeric)/86400)::int,count(*),
                count(DISTINCT o.ref),sum(o.cents) FROM chezhi_orders o JOIN chezhi_cards c USING(ref)
                WHERE o.channel<>'test' AND o.created>={start}::numeric AND o.created<{end}::numeric GROUP BY 1""",
            "orders-page": f"""SELECT {order_fields} FROM chezhi_orders o JOIN chezhi_cards c USING(ref)
                {order_filter} GROUP BY o.ref ORDER BY max(c.position) DESC LIMIT 20 OFFSET 80""",
            "orders-deep": f"""SELECT {order_fields} FROM chezhi_orders o JOIN chezhi_cards c USING(ref)
                {order_filter} GROUP BY o.ref ORDER BY max(c.position) DESC LIMIT 20 OFFSET 5000""",
        }
    else:
        page = f"""WITH page AS (
                SELECT o.ref,o.channel,o.created,o.days,o.cents,last_card.position FROM chezhi_orders o
                JOIN LATERAL (SELECT c.position FROM chezhi_cards c WHERE c.ref=o.ref
                    ORDER BY c.position DESC LIMIT 1) last_card ON true
                {order_filter} ORDER BY last_card.position DESC LIMIT 20 OFFSET {{offset}}
            )
            SELECT p.ref,p.channel,p.created,p.days,q.cards,q.activated,q.revoked,q.cards::numeric*p.cents
            FROM page p CROSS JOIN LATERAL (
                SELECT count(*) AS cards,count(*) FILTER (WHERE c.activated IS NOT NULL) AS activated,
                    count(*) FILTER (WHERE c.revoked) AS revoked FROM chezhi_cards c WHERE c.ref=p.ref
            ) q ORDER BY p.position DESC"""
        queries = {
            "overview-status": f"""SELECT count(*),
                count(*) FILTER (WHERE c.revoked),
                count(*) FILTER (WHERE NOT c.revoked AND c.expires<={now}::numeric),
                count(*) FILTER (WHERE NOT c.revoked AND (c.expires<={now}::numeric) IS NOT TRUE AND c.activated IS NULL),
                count(*) FILTER (WHERE NOT c.revoked AND (c.expires<={now}::numeric) IS NOT TRUE AND c.activated IS NOT NULL AND c.device=''),
                count(*) FILTER (WHERE NOT c.revoked AND (c.expires<={now}::numeric) IS NOT TRUE AND c.activated IS NOT NULL AND c.device<>'')
                FROM chezhi_cards c""",
            "overview-combined": f"""WITH quantities AS (
    SELECT c.ref,count(*) AS cards,
        count(*) FILTER (WHERE c.revoked) AS revoked,
        count(*) FILTER (WHERE NOT c.revoked AND c.expires<={now}::numeric) AS expired,
        count(*) FILTER (WHERE NOT c.revoked AND c.activated IS NULL) AS unused,
        count(*) FILTER (WHERE NOT c.revoked AND c.activated IS NOT NULL AND c.device='' AND (c.expires<={now}::numeric) IS NOT TRUE) AS unbound
    FROM chezhi_cards c GROUP BY c.ref
), sales AS (
    SELECT CASE WHEN o.channel<>'test' AND o.created>={start}::numeric AND o.created<{end}::numeric
        THEN floor((o.created-{start}::numeric)/86400)::int END AS day,
        q.*,o.channel<>'test' AS paid,q.cards::numeric*o.cents AS cents
    FROM quantities q JOIN chezhi_orders o USING(ref)
)
SELECT grouping(day),day,coalesce(sum(cards) FILTER (WHERE paid),0),
    count(*) FILTER (WHERE paid),coalesce(sum(cents) FILTER (WHERE paid),0),
    coalesce(sum(cards),0),coalesce(sum(revoked),0),coalesce(sum(expired),0),
    coalesce(sum(unused),0),coalesce(sum(unbound),0)
FROM sales GROUP BY GROUPING SETS ((day),())""",
            "orders-unfiltered-combined": """WITH keys AS MATERIALIZED (
    SELECT ref,max(position) AS position FROM chezhi_cards GROUP BY ref
), totals AS (
    SELECT count(*) AS n FROM keys
), page AS (
    SELECT ref,position FROM keys ORDER BY position DESC LIMIT 20
    OFFSET (SELECT (least(5::bigint,greatest(1,(n+19)/20))-1)*20 FROM totals)
), details AS (
    SELECT p.position,o.ref,o.channel,o.created,o.days,q.cards,q.activated,q.revoked,q.cards::numeric*o.cents AS cents
    FROM page p JOIN chezhi_orders o USING(ref) CROSS JOIN LATERAL (
        SELECT count(*) AS cards,count(*) FILTER (WHERE c.activated IS NOT NULL) AS activated,
            count(*) FILTER (WHERE c.revoked) AS revoked FROM chezhi_cards c WHERE c.ref=p.ref
    ) q
)
SELECT t.n,d.ref IS NOT NULL,coalesce(d.ref,''),coalesce(d.channel,''),coalesce(d.created::text,''),
    coalesce(d.days,0),coalesce(d.cards,0),coalesce(d.activated,0),coalesce(d.revoked,0),coalesce(d.cents,0)
FROM totals t LEFT JOIN details d ON true ORDER BY d.position DESC""",
            "orders-unfiltered-count": """SELECT count(*) FROM chezhi_orders o
                WHERE (''='' OR o.channel='') AND (''='' OR strpos(lower(o.ref COLLATE "pg_c_utf8"),'')>0)
                AND EXISTS (SELECT 1 FROM chezhi_cards c WHERE c.ref=o.ref)""",
            "orders-unfiltered-page": """WITH page AS (
                SELECT ref,max(position) AS position FROM chezhi_cards
                GROUP BY ref ORDER BY max(position) DESC LIMIT 20 OFFSET 80
                )
                SELECT o.ref,o.channel,o.created,o.days,q.cards,q.activated,q.revoked,q.cards::numeric*o.cents
                FROM page p JOIN chezhi_orders o USING(ref) CROSS JOIN LATERAL (
                SELECT count(*) AS cards,count(*) FILTER (WHERE c.activated IS NOT NULL) AS activated,
                count(*) FILTER (WHERE c.revoked) AS revoked FROM chezhi_cards c WHERE c.ref=p.ref
                ) q ORDER BY p.position DESC""",
            "orders-unfiltered-prior": page.replace(order_filter, "").format(offset=80),
            "overview-sales": f"""WITH quantities AS (SELECT ref,count(*) AS cards FROM chezhi_cards GROUP BY ref),
                sales AS (SELECT CASE WHEN o.created>={start}::numeric AND o.created<{end}::numeric
                    THEN floor((o.created-{start}::numeric)/86400)::int END AS day,
                    q.cards,q.cards::numeric*o.cents AS cents
                    FROM quantities q JOIN chezhi_orders o USING(ref) WHERE o.channel<>'test')
                SELECT grouping(day),day,coalesce(sum(cards),0),count(*),coalesce(sum(cents),0)
                FROM sales GROUP BY GROUPING SETS ((day),())""",
            "orders-page": page.format(offset=80),
            "orders-deep": page.format(offset=5000),
        }
    queries["cards-search-count"] = f"""SELECT (SELECT count(*) FROM chezhi_cards),count(*)
        FROM chezhi_cards c JOIN chezhi_orders o USING(ref) {cards_filter}"""
    queries["cards-unfiltered-count"] = ("SELECT (SELECT count(*) FROM chezhi_cards),count(*) "
                                          "FROM chezhi_cards c JOIN chezhi_orders o USING(ref)"
                                          if baseline else "SELECT count(*) FROM chezhi_cards")
    queries["cards-search-deep"] = f"""SELECT c.id,c.hash,c.prefix,c.days,c.ref,o.channel,o.cents,c.created,
        c.activated,c.expires,c.device,c.revoked FROM chezhi_cards c JOIN chezhi_orders o USING(ref) {cards_filter}
        ORDER BY c.position DESC LIMIT 20 OFFSET 10000"""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, query in queries.items():
        plan = json.loads(sql("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query))
        output = {"query": query, "plan": plan}
        (folder / f"{label}-{name}.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
        result = plan[0]
        root = result["Plan"]
        print(f"PLAN {label} {name} execution_ms={result['Execution Time']:.2f} "
              f"shared_hit={root.get('Shared Hit Blocks',0)} read={root.get('Shared Read Blocks',0)} "
              f"temp_written={root.get('Temp Written Blocks',0)}", flush=True)
