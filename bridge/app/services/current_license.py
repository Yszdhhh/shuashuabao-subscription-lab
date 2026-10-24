"""Current device license selection shared by the bridge and its claim mirror."""
from datetime import datetime, timezone

from bridge.app.services import tiers


def _dt(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (TypeError, ValueError):
        return None


def select_current(records, beta=False, now=None):
    """Records must already be restricted to this device's actual activations."""
    now = now or datetime.now(timezone.utc)
    floor = datetime.min.replace(tzinfo=timezone.utc)

    def state(rec):
        status = getattr(rec.get("status"), "value", rec.get("status"))
        if status == "REVOKED":
            return "REVOKED"
        if rec.get("suspended") or status == "SUSPENDED":
            return "SUSPENDED"
        exp = _dt(rec.get("expires_at"))
        if status in ("ACTIVE", "TRIAL") and exp is not None and now <= exp:
            return "ACTIVE"
        return "EXPIRED"

    records = list(records)
    if not records:
        return None
    rec = max(records, key=lambda r: (state(r) == "ACTIVE", _dt(r.get("expires_at")) or floor,
                                     _dt(r.get("created_at")) or floor, r["id"]))
    identity = tiers.resolve({**rec, "is_beta_user": bool(beta or tiers.is_beta_record(rec))})
    status = state(rec)
    exp = _dt(rec.get("expires_at"))
    return {"license_id": rec["id"], "card": rec["key"], "status": status,
            "activated": status == "ACTIVE", "currently_valid": status == "ACTIVE",
            "code": "OK" if status == "ACTIVE" else "LICENSE_" + status,
            "expires_at": exp.isoformat() if exp else None, **identity}
