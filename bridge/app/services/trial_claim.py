"""
Self-service 1-day device trial helpers (POST /v1/trials/claim).

Policy, input normalisation, client-IP resolution and a small in-process
sliding-window rate limiter. Storage/atomicity lives in SqliteEventStore
(device_trial_claims table) and InMemoryKeygenProvider.claim_device_trial.
"""
from __future__ import annotations

import ipaddress
import os
import re
import threading
import time
from collections import deque
from typing import Deque, Dict, Mapping, Optional, Tuple

TRIAL_DURATION_HOURS_DEFAULT = 24
TRIAL_PLAN = "trial_1d_auto"
TRIAL_CUSTOMER_PREFIX = "trial-auto-"
TRIAL_FEATURES = ["core", "automation", "trial_tier"]

CODE_ALREADY_USED = "TRIAL_ALREADY_USED"
CODE_NOT_ELIGIBLE = "TRIAL_NOT_ELIGIBLE"
CODE_DISABLED = "TRIAL_DISABLED"
CODE_RATE_LIMITED = "TRIAL_RATE_LIMITED"
CODE_INVALID_FINGERPRINT = "INVALID_FINGERPRINT"
CODE_INVALID_REQUEST = "INVALID_REQUEST"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FALSE = {"0", "false", "off", "no", "disabled"}

MAX_COMPONENTS = 32
MAX_COMPONENT_LEN = 256
MAX_HOSTNAME_LEN = 128
MAX_PLATFORM_LEN = 32


class TrialClaimError(Exception):
    """Business rejection with a stable public code."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message or code


def trials_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """Kill switch. Live read; default ENABLED unless explicitly turned off."""
    source = os.environ if env is None else env
    raw = str(source.get("SHUABAO_TRIALS_ENABLED", "true") or "").strip().lower()
    if raw == "":
        return True
    return raw not in _FALSE


def trial_duration_hours(env: Optional[Mapping[str, str]] = None) -> int:
    source = os.environ if env is None else env
    try:
        hours = int(str(source.get("SHUABAO_TRIAL_HOURS") or TRIAL_DURATION_HOURS_DEFAULT))
    except ValueError:
        hours = TRIAL_DURATION_HOURS_DEFAULT
    return max(1, min(hours, 24 * 7))


def normalize_fingerprint(value: object) -> str:
    """Trim + lowercase; must be exactly 64 hex chars (sha256 machine fingerprint)."""
    text = str(value or "").strip().lower()
    if not _HEX64.fullmatch(text):
        raise TrialClaimError(CODE_INVALID_FINGERPRINT, "fingerprint must be 64 hex characters")
    return text


def validate_hardware_extras(components: Mapping[str, str], hostname: Optional[str], platform: str) -> None:
    if len(components) > MAX_COMPONENTS or any(
        len(str(k)) > MAX_COMPONENT_LEN or len(str(v)) > MAX_COMPONENT_LEN
        for k, v in components.items()
    ):
        raise TrialClaimError(CODE_INVALID_REQUEST, "hardware.components too large")
    if hostname is not None and len(hostname) > MAX_HOSTNAME_LEN:
        raise TrialClaimError(CODE_INVALID_REQUEST, "hardware.hostname too long")
    if len(platform or "") > MAX_PLATFORM_LEN:
        raise TrialClaimError(CODE_INVALID_REQUEST, "hardware.platform too long")


def _parse_ip(value: str) -> Optional[str]:
    text = (value or "").strip()
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        # Bucket IPv6 by /64 so a single host cannot rotate addresses trivially.
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def client_ip_key(headers: Mapping[str, str], peer_host: Optional[str]) -> str:
    """Resolve the rate-limit key for the caller.

    Production path: Cloudflare -> cloudflared -> Caddy(18011) -> uvicorn(8010, loopback only).
    Cloudflare overwrites CF-Connecting-IP, so it is preferred. Caddy (no trusted_proxies)
    rewrites X-Forwarded-For to its own peer, so XFF is only a fallback; the uvicorn peer
    (already proxy-header aware) is the last resort.
    """
    cf = _parse_ip(headers.get("cf-connecting-ip", ""))
    if cf:
        return cf
    xff = headers.get("x-forwarded-for", "")
    if xff:
        first = _parse_ip(xff.split(",")[0])
        if first:
            return first
    return _parse_ip(peer_host or "") or "unknown"


class SlidingWindowLimiter:
    """Small thread-safe in-process sliding-window counter (single uvicorn worker)."""

    def __init__(self, limit: int, window_seconds: float, max_keys: int = 50000) -> None:
        self.limit = int(limit)
        self.window = float(window_seconds)
        self.max_keys = max_keys
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, now: Optional[float] = None) -> Tuple[bool, int]:
        """Record one attempt. Returns (allowed, retry_after_seconds)."""
        if self.limit <= 0:
            return True, 0
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                if len(self._hits) >= self.max_keys:
                    self._prune(now)
                q = self._hits.setdefault(key, deque())
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False, max(1, int(self.window - (now - q[0])) + 1)
            q.append(now)
            return True, 0

    def _prune(self, now: float) -> None:
        for k in list(self._hits.keys()):
            q = self._hits[k]
            while q and now - q[0] >= self.window:
                q.popleft()
            if not q:
                del self._hits[k]
        if len(self._hits) >= self.max_keys:
            # Still full of live keys: drop the oldest half to bound memory.
            for k in sorted(self._hits, key=lambda key: self._hits[key][-1])[: self.max_keys // 2]:
                del self._hits[k]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def _env_int(name: str, default: int, env: Optional[Mapping[str, str]] = None) -> int:
    source = os.environ if env is None else env
    try:
        return int(str(source.get(name) or default))
    except ValueError:
        return default


class TrialRateLimits:
    """Per-IP limit counts only *new-issuance* attempts (fingerprint not yet claimed);
    per-fingerprint limit counts every request for that fingerprint (retry storms)."""

    def __init__(self, env: Optional[Mapping[str, str]] = None) -> None:
        window = _env_int("SHUABAO_TRIAL_RATE_WINDOW_SECONDS", 3600, env)
        self.per_ip = SlidingWindowLimiter(_env_int("SHUABAO_TRIAL_RATE_PER_IP", 10, env), window)
        self.per_fp = SlidingWindowLimiter(_env_int("SHUABAO_TRIAL_RATE_PER_FINGERPRINT", 30, env), window)

    def reset(self) -> None:
        self.per_ip.reset()
        self.per_fp.reset()
