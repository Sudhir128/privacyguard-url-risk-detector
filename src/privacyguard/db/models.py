import json

from privacyguard.config import get_settings
from privacyguard.db.connection import get_connection, get_supabase_client, placeholder


def _row_to_dict(row) -> dict:
    return dict(row)


def _insert_returning_id(cursor, query: str, params: tuple) -> int:
    settings = get_settings()
    if settings.db_type == "postgres":
        cursor.execute(query + " RETURNING id", params)
        return cursor.fetchone()["id"]
    cursor.execute(query, params)
    return cursor.lastrowid


def create_session(source: str = "manual", total_urls: int = 0) -> int:
    settings = get_settings()
    if settings.db_type == "supabase":
        client = get_supabase_client()
        res = (
            client.table("scan_sessions")
            .insert({"source": source, "total_urls": total_urls})
            .execute()
        )
        if res.data and len(res.data) > 0:
            return res.data[0]["id"]
        return 0

    ph = placeholder()
    query = f"INSERT INTO scan_sessions (source, total_urls) VALUES ({ph}, {ph})"
    with get_connection() as conn:
        cursor = conn.cursor()
        session_id = _insert_returning_id(cursor, query, (source, total_urls))
        cursor.close()
    return session_id


def save_scan(
    url: str,
    score: float,
    risk_label: str,
    domain: str | None = None,
    is_tracker: bool = False,
    is_phishing: bool = False,
    matched_brand: str | None = None,
    predicted_label: str | None = None,
    confidence: float | None = None,
    verdict: str | None = None,
    explanation: list[str] | None = None,
    session_id: int | None = None,
) -> int:
    settings = get_settings()
    explanation_json = json.dumps(explanation or [])
    if settings.db_type == "supabase":
        client = get_supabase_client()
        payload = {
            "url": url,
            "domain": domain,
            "score": score,
            "risk_label": risk_label,
            "is_tracker": bool(is_tracker),
            "is_phishing": bool(is_phishing),
            "matched_brand": matched_brand,
            "predicted_label": predicted_label,
            "confidence": confidence,
            "verdict": verdict,
            "explanation": explanation_json,
        }
        if session_id is not None:
            payload["session_id"] = session_id

        res = client.table("url_scans").insert(payload).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]["id"]
        return 0

    ph = placeholder()
    query = f"""
        INSERT INTO url_scans
        (session_id, url, domain, score, risk_label, is_tracker, is_phishing,
         matched_brand, predicted_label, confidence, verdict, explanation)
        VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
    """
    params = (
        session_id,
        url,
        domain,
        score,
        risk_label,
        bool(is_tracker),
        bool(is_phishing),
        matched_brand,
        predicted_label,
        confidence,
        verdict,
        explanation_json,
    )
    with get_connection() as conn:
        cursor = conn.cursor()
        scan_id = _insert_returning_id(cursor, query, params)
        cursor.close()
    return scan_id


def get_history(limit: int = 50, offset: int = 0, risk_label: str | None = None) -> list[dict]:
    settings = get_settings()
    if settings.db_type == "supabase":
        client = get_supabase_client()
        query = client.table("url_scans").select("*")
        if risk_label:
            query = query.eq("risk_label", risk_label)
        query = query.order("created_at", desc=True).order("id", desc=True).range(offset, offset + limit - 1)
        res = query.execute()
        rows = res.data or []
        for row in rows:
            if row.get("explanation"):
                if isinstance(row["explanation"], str):
                    try:
                        row["explanation"] = json.loads(row["explanation"])
                    except (TypeError, ValueError):
                        row["explanation"] = []
        return rows

    ph = placeholder()
    if risk_label:
        query = f"""
            SELECT * FROM url_scans
            WHERE risk_label = {ph}
            ORDER BY created_at DESC, id DESC
            LIMIT {ph} OFFSET {ph}
        """
        params = (risk_label, limit, offset)
    else:
        query = f"""
            SELECT * FROM url_scans
            ORDER BY created_at DESC, id DESC
            LIMIT {ph} OFFSET {ph}
        """
        params = (limit, offset)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = [_row_to_dict(r) for r in cursor.fetchall()]
        cursor.close()

    for row in rows:
        if row.get("explanation"):
            try:
                row["explanation"] = json.loads(row["explanation"])
            except (TypeError, ValueError):
                row["explanation"] = []
    return rows


def get_stats() -> dict:
    settings = get_settings()
    if settings.db_type == "supabase":
        client = get_supabase_client()
        res = client.table("url_scans").select("risk_label, is_tracker, score").execute()
        rows = res.data or []
        total = len(rows)
        distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        trackers_found = 0
        critical_alerts = 0
        scores = []
        for r in rows:
            label = r.get("risk_label")
            if label in distribution:
                distribution[label] += 1
            if r.get("is_tracker"):
                trackers_found += 1
            if label == "CRITICAL":
                critical_alerts += 1
            if r.get("score") is not None:
                scores.append(float(r["score"]))
        avg_score = (sum(scores) / len(scores)) if scores else 0
        privacy_score = max(0, round(100 - (avg_score * 10)))
        return {
            "total_scans": total,
            "risk_distribution": distribution,
            "trackers_found": trackers_found,
            "critical_alerts": critical_alerts,
            "privacy_score": privacy_score,
        }

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS c FROM url_scans")
        total = _row_to_dict(cursor.fetchone())["c"]

        cursor.execute("SELECT risk_label, COUNT(*) AS c FROM url_scans GROUP BY risk_label")
        distribution = {row["risk_label"]: row["c"] for row in (_row_to_dict(r) for r in cursor.fetchall())}

        cursor.execute("SELECT COUNT(*) AS c FROM url_scans WHERE is_tracker = 1 OR is_tracker = true")
        trackers_found = _row_to_dict(cursor.fetchone())["c"]

        cursor.execute("SELECT COUNT(*) AS c FROM url_scans WHERE risk_label = 'CRITICAL'")
        critical_alerts = _row_to_dict(cursor.fetchone())["c"]

        cursor.execute("SELECT AVG(score) AS avg_score FROM url_scans")
        avg_row = _row_to_dict(cursor.fetchone())
        avg_score = avg_row["avg_score"] or 0
        cursor.close()

    privacy_score = max(0, round(100 - (avg_score * 10)))

    return {
        "total_scans": total,
        "risk_distribution": {
            "LOW": distribution.get("LOW", 0),
            "MEDIUM": distribution.get("MEDIUM", 0),
            "HIGH": distribution.get("HIGH", 0),
            "CRITICAL": distribution.get("CRITICAL", 0),
        },
        "trackers_found": trackers_found,
        "critical_alerts": critical_alerts,
        "privacy_score": privacy_score,
    }


def get_top_trackers(limit: int = 10) -> list[dict]:
    settings = get_settings()
    if settings.db_type == "supabase":
        client = get_supabase_client()
        res = client.table("url_scans").select("domain").eq("is_tracker", True).not_.is_("domain", "null").execute()
        rows = res.data or []
        counts = {}
        for r in rows:
            dom = r.get("domain")
            if dom:
                counts[dom] = counts.get(dom, 0) + 1
        sorted_trackers = sorted(
            [{"domain": k, "count": v} for k, v in counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )
        return sorted_trackers[:limit]

    ph = placeholder()
    query = f"""
        SELECT domain, COUNT(*) AS count
        FROM url_scans
        WHERE (is_tracker = 1 OR is_tracker = true) AND domain IS NOT NULL
        GROUP BY domain
        ORDER BY count DESC
        LIMIT {ph}
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (limit,))
        rows = [_row_to_dict(r) for r in cursor.fetchall()]
        cursor.close()
    return rows
