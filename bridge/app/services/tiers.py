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
    "go":    {"tier_name": "Go 订阅",       "plan": "go_daily",       "duration_days": 1, "pip_background": False},
    "plus":  {"tier_name": "Plus 订阅",     "plan": "plus_daily",     "duration_days": 1, "pip_background": False},
    "pro":   {"tier_name": "Pro 订阅",      "plan": "pro_weekly",     "duration_days": 7, "pip_background": False},
    "max":   {"tier_name": "Max 订阅",      "plan": "max_monthly",    "duration_days": 30, "pip_background": False},
    "ultra": {"tier_name": "Ultra 永久用户", "plan": "ultra_permanent", "duration_days": None, "pip_background": False},
    "test":  {"tier_name": "内测用户",       "plan": "trial_1d",       "duration_days": 1, "pip_background": False},   # input alias of beta/trial
    # r7.1 identity: internal/trial cards are labelled by WHO holds them, not by plan.
    "beta":  {"tier_name": "内测用户",       "plan": "trial_1d",       "duration_days": 1, "pip_background": False},   # historical beta users only
    "trial": {"tier_name": "Go 订阅",           "plan": "trial_1d",       "duration_days": 1, "pip_background": False},   # post-cutover non-beta trial
}
TIER_ORDER = ("go", "plus", "pro", "max", "ultra", "test", "beta", "trial")
INTERNAL_TIERS = ("test", "beta", "trial")
PAID_TIERS = ("go", "plus", "pro", "max")
# r7.1: a user without any card (validate NOT_FOUND / no binding) is shown as 未开通.
NO_SUBSCRIPTION = {"plan": None, "tier": "none", "tier_name": "未开通", "is_beta_user": False}
FORMAL_TIERS = ("go", "plus", "pro", "max", "ultra")

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
    # 2026-10-24 webpage alignment (supersedes r7.1 Q5 naming): canonical stored plans are
    # go_daily/plus_daily/pro_weekly/max_monthly/ultra_permanent (Plus=1d, Pro=7d, Max=30d).
    # Legacy plus_weekly/pro_monthly cards stay readable and resolve to plus/pro.
    "go_daily": "go",
    "plus_daily": "plus",
    "pro_weekly": "pro",
    "max_monthly": "max",
    "plus_weekly": "plus",
    "ultra_permanent": "ultra",
}
# r7.1 Q5: alias plan names accepted on input and REWRITTEN to the canonical stored name.
PLAN_ALIASES: dict[str, str] = {"go_1d": "go", "plus_1d": "plus", "pro_7d": "pro", "max_30d": "max",
                                "plus_7d": "plus", "pro_30d": "pro", "ultra_lifetime": "ultra"}
PLAN_REWRITE: dict[str, str] = {"go_1d": "go_daily", "plus_1d": "plus_daily", "pro_7d": "pro_weekly",
                                "max_30d": "max_monthly", "plus_7d": "plus_daily", "pro_30d": "pro_weekly",
                                "ultra_lifetime": "ultra_permanent"}
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


def is_beta_record(rec: Mapping[str, Any]) -> bool:
    """r7.1: persisted flag set by scripts/snapshot_beta_r71.py at cutover (or on activation of a
    flagged card / by a beta fingerprint). Never derived from plan."""
    meta = rec.get("metadata") or {}
    return bool(rec.get("is_beta_user") is True or meta.get("is_beta_user") is True)


def resolve(rec: Mapping[str, Any]) -> dict[str, Any]:
    """Return {plan, tier, tier_name, is_beta_user} for a stored record - explicit tier wins.
    r7.1: an internal card (stored tier test/beta/trial, or a test_*/trial_* plan) resolves to
    ``beta`` (内测用户) ONLY when the record carries the persisted beta flag; otherwise ``trial`` (试用).
    ``test`` stays accepted as an alias on read."""
    plan = str(rec.get("plan") or "")
    tier = rec.get("tier")
    if not is_tier(tier):
        meta = rec.get("metadata") or {}
        tier = meta.get("tier") if is_tier(meta.get("tier")) else derive_tier(plan)
    beta = is_beta_record(rec)
    if tier in INTERNAL_TIERS:
        tier = "beta" if beta else "trial"
    return {"plan": plan, "tier": tier, "tier_name": tier_name(tier), "is_beta_user": beta}


def plan_for(tier: str, days: Optional[int] = None, starts_on_first: bool = False) -> str:
    """Canonical plan for a tier. A 1-day internal card is ``trial_1d``; other internal
    durations keep the legacy ``test_{days}d[_first_act]`` form (tier stays ``test``)."""
    if tier in INTERNAL_TIERS and days and int(days) != 1:
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


def canonical_plan(plan: Optional[str]) -> str:
    """r7.1 Q5: the plan name to STORE for a requested plan (aliases rewritten)."""
    p = str(plan or "").strip().lower()
    return PLAN_REWRITE.get(p, p)
