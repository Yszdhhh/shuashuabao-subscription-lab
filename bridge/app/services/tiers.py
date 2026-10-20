"""BATCH C: unified four-tier subscription identity (single source of truth).

Every license record carries ``plan``; new records also persist ``tier`` and
``tier_name`` (inside local_licenses.data_json). Records without an explicit tier
(legacy cards) derive it from ``plan`` via ``LEGACY_PLAN_TIER`` / prefix rules, so
no backfill is required for them to return tier fields.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Optional

# Lifetime policy: a fixed far-future expiry so every existing expiry comparison,
# grace computation and permit TTL clamp keeps working without a NULL special case.
LIFETIME_EXPIRES_AT = datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

TIERS: dict[str, dict[str, Any]] = {
    "go":    {"tier_name": "Go 订阅",       "plan": "go_1d",          "duration_days": 1},
    "plus":  {"tier_name": "Plus 订阅",     "plan": "plus_7d",        "duration_days": 7},
    "pro":   {"tier_name": "Pro 订阅",      "plan": "pro_30d",        "duration_days": 30},
    "ultra": {"tier_name": "Ultra 永久用户", "plan": "ultra_lifetime", "duration_days": None},
    "test":  {"tier_name": "内测用户",       "plan": "trial_1d",       "duration_days": 1},
}
TIER_ORDER = ("go", "plus", "pro", "ultra", "test")
FORMAL_TIERS = ("go", "plus", "pro", "ultra")

# Legacy plan -> tier. Exact matches first; then prefix rules (see derive_tier).
LEGACY_PLAN_TIER: dict[str, str] = {
    "go_1d": "go",
    "plus_7d": "plus",
    "pro_30d": "pro",
    "ultra_lifetime": "ultra",
    "trial_1d": "test",
    "trial_1d_auto": "test",   # POST /v1/trials/claim self-service trial
    "trial_7d": "test",        # legacy keygate trial plan
    "pro_monthly": "pro",      # SERVER_PLAN_POLICIES (FOSSBilling) 30 d
    "pro_annual": "pro",       # 365 d, still Pro feature set
    "enterprise": "pro",       # OPEN QUESTION (Owner): pro or ultra?
    # r7 Owner ruling 1: accepted ALIASES (canonical plans stay go_1d/plus_7d/pro_30d/ultra_lifetime/trial_1d)
    "go_daily": "go",
    "plus_weekly": "plus",
    "ultra_permanent": "ultra",
}
# r7 ruling 1: alias plan names accepted on input (issuance ``plan`` field) and on read.
PLAN_ALIASES: dict[str, str] = {"go_daily": "go", "plus_weekly": "plus", "pro_monthly": "pro",
                                "ultra_permanent": "ultra"}
CANONICAL_PLANS = {t: v["plan"] for t, v in TIERS.items()}
LEGACY_PREFIX_TIER = (("test_", "test"), ("trial_", "test"))
DEFAULT_TIER = "test"          # unknown plans are shown as 内测用户, never upgraded silently


def is_tier(value: object) -> bool:
    return isinstance(value, str) and value in TIERS


def tier_name(tier: str) -> str:
    return TIERS[tier]["tier_name"]


def derive_tier(plan: Optional[str]) -> str:
    p = str(plan or "").strip()
    if p in LEGACY_PLAN_TIER:
        return LEGACY_PLAN_TIER[p]
    for prefix, tier in LEGACY_PREFIX_TIER:
        if p.startswith(prefix):
            return tier
    return DEFAULT_TIER


def resolve(rec: Mapping[str, Any]) -> dict[str, str]:
    """Return {plan, tier, tier_name} for a stored record (dict) - explicit tier wins."""
    plan = str(rec.get("plan") or "")
    tier = rec.get("tier")
    if not is_tier(tier):
        meta = rec.get("metadata") or {}
        tier = meta.get("tier") if is_tier(meta.get("tier")) else derive_tier(plan)
    return {"plan": plan, "tier": tier, "tier_name": tier_name(tier)}


def plan_for(tier: str, days: Optional[int] = None, starts_on_first: bool = False) -> str:
    """Canonical plan for a tier. A 1-day internal card is ``trial_1d``; other internal
    durations keep the legacy ``test_{days}d[_first_act]`` form (tier stays ``test``)."""
    if tier == "test" and days and int(days) != 1:
        return f"test_{int(days)}d" + ("_first_act" if starts_on_first else "")
    return TIERS[tier]["plan"]


def tier_from_plan_input(plan: Optional[str]) -> Optional[str]:
    """r7: map a requested plan (canonical or alias) to its tier; None if not a known plan name."""
    p = str(plan or "").strip().lower()
    if p in PLAN_ALIASES:
        return PLAN_ALIASES[p]
    for t, cp in CANONICAL_PLANS.items():
        if p == cp:
            return t
    return None
