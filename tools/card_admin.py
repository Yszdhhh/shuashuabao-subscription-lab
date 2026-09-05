"""
ShuaBao License Card Operator CLI.
Minimal, secure operator tool for bulk card generation, inventory management, and inspection.
Zero LLM / Grok / AI dependencies; Python stdlib only.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Ensure repo root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from bridge.app.core.cards import (
    CARD_PLAN_DURATIONS,
    mask_card_code,
    parse_plan_duration,
)
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore
from contracts.entitlement import LicenseDTO, LicenseStatus

_DEFAULT_DB_PATH = os.environ.get("SUBSCRIPTION_DB_PATH", "./data/subscription_state.db")


def _get_provider(db_path: str) -> tuple[SqliteEventStore, InMemoryKeygenProvider]:
    # Ensure parent directory of db exists
    resolved = Path(db_path).resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    store = SqliteEventStore(str(resolved))
    provider = InMemoryKeygenProvider(event_store=store)
    return store, provider


def _api_request(
    api_url: str,
    endpoint: str,
    method: str = "GET",
    data: Optional[dict] = None,
    admin_key: Optional[str] = None,
) -> dict:
    """Execute authenticated HTTP request to the authoritative backend Admin API."""
    url = f"{api_url.rstrip('/')}{endpoint}"
    headers = {
        "User-Agent": "ShuaBao-CardAdmin/1.0",
        "Content-Type": "application/json",
    }
    if admin_key:
        headers["X-Admin-Key"] = admin_key
        # Also include Basic Auth for maximum server compatibility
        b64_auth = base64.b64encode(f"admin:{admin_key}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {b64_auth}"

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            resp_body = resp.read().decode("utf-8")
            return json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as exc:
        err_msg = exc.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(err_msg)
            detail = err_json.get("detail", err_msg)
        except Exception:
            detail = err_msg
        raise RuntimeError(f"Admin API error ({exc.code}): {detail}")
    except Exception as exc:
        raise RuntimeError(f"Admin API request failed: {exc}")


async def _generate_cards(
    plan: str,
    count: int,
    output_path: str,
    note: Optional[str] = None,
    duration_seconds: Optional[int] = None,
    batch_id: Optional[str] = None,
    device_limit: int = 1,
    prefix: Optional[str] = None,
    db_path: str = _DEFAULT_DB_PATH,
    api_url: Optional[str] = None,
    admin_key: Optional[str] = None,
) -> None:
    plan_name, duration_sec = parse_plan_duration(plan, duration_seconds)

    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    temp_file = out_file.with_suffix(f".tmp.{os.getpid()}")

    if api_url:
        # Remote operator mode: talk to authoritative backend via HTTPS Admin API
        payload = {
            "plan": plan_name,
            "count": count,
            "duration_seconds": duration_sec,
            "batch_id": batch_id,
            "operator_note": note,
            "device_limit": device_limit,
            "prefix": prefix,
        }
        res = _api_request(api_url, "/admin/cards/batches", method="POST", data=payload, admin_key=admin_key)
        actual_batch_id = res["batch_id"]
        cards_data = res["cards"]

        try:
            with open(temp_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["code", "plan", "duration_seconds", "batch_id", "created_at"])
                for c in cards_data:
                    writer.writerow([c["code"], c["plan"], c["duration_seconds"], actual_batch_id, c["created_at"]])
                f.flush()
                os.fsync(f.fileno())

            # Atomically rename
            os.replace(temp_file, out_file)

            # Mark batch COMMITTED remotely
            _api_request(api_url, f"/admin/cards/batches/{actual_batch_id}/commit", method="POST", admin_key=admin_key)
        except Exception:
            # Mark batch FAILED remotely
            try:
                _api_request(api_url, f"/admin/cards/batches/{actual_batch_id}/fail", method="POST", admin_key=admin_key)
            except Exception:
                pass
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass
            raise

        sample_masked = mask_card_code(cards_data[0]["code"]) if cards_data else "N/A"
        authority_desc = f"Remote API ({api_url})"
        card_count_done = len(cards_data)
    else:
        # Local SQLite mode: direct execution against local store
        store, provider = _get_provider(db_path)
        actual_batch_id, card_recs = provider.prepare_cards(
            count=count,
            plan=plan_name,
            duration_seconds=duration_sec,
            batch_id=batch_id,
            operator_note=note,
            device_limit=device_limit,
            prefix=prefix,
        )

        cards = await provider.commit_batch(
            batch_id=actual_batch_id,
            plan=plan_name,
            duration_seconds=duration_sec,
            cards=card_recs,
            operator_note=note,
            status="PREPARED",
        )

        try:
            with open(temp_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["code", "plan", "duration_seconds", "batch_id", "created_at"])
                for c in card_recs:
                    created_str = c["created_at"].astimezone(timezone.utc).isoformat() if hasattr(c["created_at"], "astimezone") else str(c["created_at"])
                    writer.writerow([c["key"], c["plan"], c["duration_seconds"], actual_batch_id, created_str])
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_file, out_file)

            if hasattr(store, "update_batch_status"):
                store.update_batch_status(actual_batch_id, "COMMITTED")
            if hasattr(provider, "update_batch_status"):
                provider.update_batch_status(actual_batch_id, "COMMITTED")
        except Exception:
            if hasattr(store, "update_batch_status"):
                store.update_batch_status(actual_batch_id, "FAILED")
            if hasattr(provider, "update_batch_status"):
                provider.update_batch_status(actual_batch_id, "FAILED")
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass
            raise

        sample_masked = mask_card_code(cards[0].license_key) if cards else "N/A"
        authority_desc = f"Local SQLite ({db_path})"
        card_count_done = len(cards)

    print("=" * 60)
    print("  ShuaBao License Card Batch Generation Completed")
    print("=" * 60)
    print(f"  Batch ID:         {actual_batch_id}")
    print(f"  Plan:             {plan_name}")
    print(f"  Duration:         {duration_sec} seconds ({duration_sec // 86400}d)")
    print(f"  Card Count:       {card_count_done}")
    if note:
        print(f"  Operator Note:    {note}")
    print(f"  Sample Masked:    {sample_masked}")
    print(f"  CSV Output:       {out_file}")
    print(f"  Authority:        {authority_desc}")
    print("=" * 60)
    print("  NOTE: Plaintext card codes are written ONLY to the output CSV above.")
    print("  Treat the exported CSV securely. Do NOT commit plaintext cards.")


def _list_batches(
    db_path: str = _DEFAULT_DB_PATH,
    api_url: Optional[str] = None,
    admin_key: Optional[str] = None,
) -> None:
    if api_url:
        res = _api_request(api_url, "/admin/cards/batches", method="GET", admin_key=admin_key)
        batches = res.get("batches", [])
    else:
        store, _ = _get_provider(db_path)
        batches = store.list_batches()

    if not batches:
        print("No card batches found.")
        return

    print(f"{'BATCH_ID':<32} {'PLAN':<8} {'DURATION':<10} {'COUNT':<8} {'STATUS':<12} {'CREATED_AT':<26} {'NOTE'}")
    print("-" * 115)
    for b in batches:
        dur_str = f"{b['duration_seconds']}s"
        note = b.get("operator_note") or ""
        status = b.get("status", "COMMITTED")
        print(f"{b['batch_id']:<32} {b['plan']:<8} {dur_str:<10} {b['card_count']:<8} {status:<12} {b['created_at']:<26} {note}")


def _list_cards(
    batch_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    db_path: str = _DEFAULT_DB_PATH,
    api_url: Optional[str] = None,
    admin_key: Optional[str] = None,
) -> None:
    if api_url:
        params = []
        if batch_id:
            params.append(f"batch_id={urllib.parse.quote(batch_id)}")
        if status:
            params.append(f"status={urllib.parse.quote(status)}")
        params.append(f"limit={limit}")
        qs = f"?{'&'.join(params)}"
        res = _api_request(api_url, f"/admin/cards{qs}", method="GET", admin_key=admin_key)
        cards = res.get("cards", [])
        total_count = res.get("total", len(cards))

        print(f"{'ID':<18} {'MASKED_CODE':<30} {'STATUS':<10} {'PLAN':<8} {'ACTIVATED_AT':<22} {'EXPIRES_AT':<22} {'BATCH_ID'}")
        print("-" * 130)
        for d in cards:
            masked = d.get("masked_code", "")
            st_str = d.get("status", "")
            act_str = d.get("activated_at") or "NULL"
            exp_str = d.get("expires_at") or "NULL"
            b_id = d.get("batch_id") or ""
            print(f"{d.get('id', ''):<18} {masked:<30} {st_str:<10} {d.get('plan', ''):<8} {act_str:<22} {exp_str:<22} {b_id}")
        print(f"\nTotal shown: {len(cards)} of {total_count} matching cards.")
    else:
        store, _ = _get_provider(db_path)
        licenses = store.load_local_licenses()

        filtered = []
        status_filter = status.upper() if status else None

        for lic_id, d in licenses.items():
            if batch_id:
                lic_batch = d.get("metadata", {}).get("batch_id") or d.get("batch_id")
                if lic_batch != batch_id:
                    continue
            if status_filter:
                lic_status = d.get("status")
                status_val = lic_status.value if isinstance(lic_status, LicenseStatus) else str(lic_status)
                if status_val != status_filter:
                    continue
            filtered.append(d)

        filtered.sort(key=lambda r: r.get("created_at") or datetime.min, reverse=True)
        shown = filtered[:limit]

        print(f"{'ID':<18} {'MASKED_CODE':<30} {'STATUS':<10} {'PLAN':<8} {'ACTIVATED_AT':<22} {'EXPIRES_AT':<22} {'BATCH_ID'}")
        print("-" * 130)
        for d in shown:
            masked = mask_card_code(d.get("key", ""))
            st = d.get("status")
            st_str = st.value if isinstance(st, LicenseStatus) else str(st)
            act = d.get("activated_at")
            act_str = act.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if act else "NULL"
            exp = d.get("expires_at")
            exp_str = exp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if exp else "NULL"
            b_id = d.get("metadata", {}).get("batch_id") or d.get("batch_id") or ""
            print(f"{d.get('id', ''):<18} {masked:<30} {st_str:<10} {d.get('plan', ''):<8} {act_str:<22} {exp_str:<22} {b_id}")

        print(f"\nTotal shown: {len(shown)} of {len(filtered)} matching cards.")


def _inspect_card(
    card_or_id: str,
    db_path: str = _DEFAULT_DB_PATH,
    api_url: Optional[str] = None,
    admin_key: Optional[str] = None,
) -> None:
    if api_url:
        res = _api_request(api_url, f"/admin/cards/{urllib.parse.quote(card_or_id)}", method="GET", admin_key=admin_key)
        target = res
        masked = target.get("masked_code", "")
        st_str = target.get("status", "")
        print("=" * 60)
        print("  License Card Inspection (Authoritative Backend)")
        print("=" * 60)
        print(f"  License ID:       {target.get('id')}")
        print(f"  Masked Code:      {masked}")
        print(f"  Status:           {st_str}")
        print(f"  Plan:             {target.get('plan')}")
        print(f"  Duration:         {target.get('duration_seconds')} seconds")
        print(f"  Created At:       {target.get('created_at')}")
        print(f"  Activated At:     {target.get('activated_at') or 'NULL (Unused)'}")
        print(f"  Expires At:       {target.get('expires_at') or 'NULL (Unused)'}")
        print(f"  Batch ID:         {target.get('batch_id') or 'N/A'}")
        print(f"  Device Limit:     {target.get('device_limit', 1)}")
        if target.get("devices"):
            print(f"  Bound Devices:    {target.get('devices')}")
        print("=" * 60)
    else:
        store, provider = _get_provider(db_path)
        licenses = store.load_local_licenses()

        target = None
        for lic_id, d in licenses.items():
            if lic_id == card_or_id or d.get("key") == card_or_id:
                target = d
                break

        if not target:
            print(f"Card or license '{card_or_id}' not found.")
            return

        masked = mask_card_code(target.get("key", ""))
        st = target.get("status")
        st_str = st.value if isinstance(st, LicenseStatus) else str(st)

        print("=" * 60)
        print("  License Card Inspection (Local SQLite)")
        print("=" * 60)
        print(f"  License ID:       {target.get('id')}")
        print(f"  Masked Code:      {masked}")
        print(f"  Status:           {st_str}")
        print(f"  Plan:             {target.get('plan')}")
        print(f"  Duration:         {target.get('duration_seconds')} seconds")
        print(f"  Created At:       {target.get('created_at')}")
        print(f"  Activated At:     {target.get('activated_at') or 'NULL (Unused)'}")
        print(f"  Expires At:       {target.get('expires_at') or 'NULL (Unused)'}")
        print(f"  Batch ID:         {target.get('metadata', {}).get('batch_id') or 'N/A'}")
        print(f"  Device Limit:     {target.get('device_limit', 1)}")
        print("=" * 60)


def main() -> None:
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--api-url",
        default=os.environ.get("SHUABAO_ADMIN_URL") or os.environ.get("SHUABAO_API_URL"),
        help="Authoritative backend URL (e.g. https://api.shuashuabao.com). If provided, operations execute against remote authoritative backend via HTTPS Admin API instead of local SQLite.",
    )
    common_parser.add_argument(
        "--admin-key",
        default=os.environ.get("SUBSCRIPTION_ADMIN_PASSWORD") or os.environ.get("SUBSCRIPTION_ADMIN_KEY"),
        help="Admin password or API key for remote HTTPS Admin API authentication.",
    )
    common_parser.add_argument(
        "--db",
        default=_DEFAULT_DB_PATH,
        help="Path to SQLite database (used only in local mode when --api-url is not set).",
    )

    parser = argparse.ArgumentParser(
        prog="card_admin",
        description="ShuaBao License Card Operations CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate subcommand
    gen_parser = subparsers.add_parser("generate", parents=[common_parser], help="Bulk generate license cards")
    gen_parser.add_argument("--plan", required=True, help="Plan tier (1d, 3d, 7d, 30d)")
    gen_parser.add_argument("--count", type=int, default=1, help="Number of cards to generate (default: 1)")
    gen_parser.add_argument("--output", required=True, help="Path to write plaintext CSV output")
    gen_parser.add_argument("--note", default=None, help="Optional operator note for this batch")
    gen_parser.add_argument("--duration-seconds", type=int, default=None, help="Override explicit duration in seconds")
    gen_parser.add_argument("--batch-id", default=None, help="Custom batch ID (default: auto-generated)")
    gen_parser.add_argument("--device-limit", type=int, default=1, help="Device activation limit (default: 1)")
    gen_parser.add_argument("--prefix", default=None, help="Custom card prefix (e.g. SSB-D1-)")

    # list-batches subcommand
    lb_parser = subparsers.add_parser("list-batches", parents=[common_parser], help="List all generated card batches")

    # list-cards subcommand
    lc_parser = subparsers.add_parser("list-cards", parents=[common_parser], help="List license cards with masked codes")
    lc_parser.add_argument("--batch-id", default=None, help="Filter by batch ID")
    lc_parser.add_argument("--status", default=None, help="Filter by status (UNUSED, ACTIVE, EXPIRED, REVOKED)")
    lc_parser.add_argument("--limit", type=int, default=50, help="Max cards to list (default: 50)")

    # inspect subcommand
    insp_parser = subparsers.add_parser("inspect", parents=[common_parser], help="Inspect a license card by ID or code")
    insp_parser.add_argument("card_or_id", help="Card code or license ID to inspect")

    args = parser.parse_args()

    if args.command == "generate":
        asyncio.run(
            _generate_cards(
                plan=args.plan,
                count=args.count,
                output_path=args.output,
                note=args.note,
                duration_seconds=args.duration_seconds,
                batch_id=args.batch_id,
                device_limit=args.device_limit,
                prefix=args.prefix,
                db_path=args.db,
                api_url=args.api_url,
                admin_key=args.admin_key,
            )
        )
    elif args.command == "list-batches":
        _list_batches(db_path=args.db, api_url=args.api_url, admin_key=args.admin_key)
    elif args.command == "list-cards":
        _list_cards(
            batch_id=args.batch_id,
            status=args.status,
            limit=args.limit,
            db_path=args.db,
            api_url=args.api_url,
            admin_key=args.admin_key,
        )
    elif args.command == "inspect":
        _inspect_card(
            card_or_id=args.card_or_id,
            db_path=args.db,
            api_url=args.api_url,
            admin_key=args.admin_key,
        )


if __name__ == "__main__":
    main()
