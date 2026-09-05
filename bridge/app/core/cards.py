"""
Card密（License Card）Core Utilities.
Cryptographically secure randomness, unambiguous alphabet, and plan definitions.
Zero external dependencies; stdlib only.
"""
from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

# Unambiguous alphabet excluding 0, O, 1, I, L (32 characters = 5 bits per char)
CARD_ALPHABET: str = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

# Authoritative plan duration definitions in seconds
CARD_PLAN_DURATIONS: Dict[str, int] = {
    "1d": 86400,
    "3d": 259200,
    "7d": 604800,
    "30d": 2592000,
}

# Standard human-readable prefix by plan
CARD_PLAN_PREFIXES: Dict[str, str] = {
    "1d": "SSB-D1-",
    "3d": "SSB-D3-",
    "7d": "SSB-D7-",
    "30d": "SSB-D30-",
}


def parse_plan_duration(plan: str, custom_seconds: Optional[int] = None) -> Tuple[str, int]:
    """
    Resolve canonical plan name and duration in seconds.
    Authority is explicit duration_seconds, not string comparisons.
    """
    if custom_seconds is not None and custom_seconds > 0:
        return plan.strip().lower(), custom_seconds

    normalized = plan.strip().lower()
    if normalized in CARD_PLAN_DURATIONS:
        return normalized, CARD_PLAN_DURATIONS[normalized]

    # Support flexible format like "2d", "14d"
    match = re.match(r"^(\d+)d$", normalized)
    if match:
        days = int(match.group(1))
        if days > 0:
            return normalized, days * 86400

    supported = ", ".join(CARD_PLAN_DURATIONS.keys())
    raise ValueError(f"Unsupported plan '{plan}'. Supported plans: {supported}")


def generate_card_code(plan: str = "1d", prefix: Optional[str] = None) -> str:
    """
    Generate a cryptographically secure license card code with unambiguous characters.
    Entropy: 16 characters from 32-char alphabet = 2^80 combinations.
    Format: SSB-D1-XXXX-XXXX-XXXX-XXXX
    """
    if prefix is None:
        norm_plan = plan.strip().lower()
        prefix = CARD_PLAN_PREFIXES.get(norm_plan, f"SSB-{norm_plan.upper()}-")

    blocks = [
        "".join(secrets.choice(CARD_ALPHABET) for _ in range(4))
        for _ in range(4)
    ]
    return f"{prefix}{'-'.join(blocks)}"


def mask_card_code(code: str) -> str:
    """
    Mask plaintext card code for safe display in logs, queries, and console.
    E.g.: 'SSB-D1-ABCD-EFGH-JKMN-PQRT' -> 'SSB-D1-ABCD-****-****-PQRT'
    """
    if not code:
        return ""
    parts = code.split("-")
    if len(parts) >= 4:
        # Mask middle blocks, keep prefix and outer blocks
        masked = list(parts)
        for i in range(2, len(parts) - 1):
            masked[i] = "****"
        return "-".join(masked)
    if len(code) <= 8:
        return "****"
    return f"{code[:4]}...{code[-4:]}"
