#!/usr/bin/env python3
"""pool.json v1 -> v2 (r3, Batch B, NOT run in prod). Reads SRC read-only, writes a NEW file DST (0600,
O_EXCL), verifies round-trip, prints redacted counts only. Never modifies or deletes SRC.
  migrate_pool.py --src pool.json --dst pool.v2.json --key-file trial_pool.key [--gen-key]"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trial_store_v2 as v2

ap = argparse.ArgumentParser()
ap.add_argument("--src", required=True); ap.add_argument("--dst", required=True); ap.add_argument("--key-file", required=True)
ap.add_argument("--gen-key", action="store_true")
a = ap.parse_args()
if a.gen_key:
    v2.Keys.generate(a.key_file)
keys = v2.Keys.load(a.key_file)
src = json.load(open(a.src, encoding="utf-8"))
dst = v2.migrate(src, keys)
# round-trip verification (in memory only)
cards_src = sorted(list(src.get("pool") or []) + list(src.get("bonus_pool") or []) + list((src.get("claims") or {}).values())
                   + [c for v in (src.get("ref_cards") or {}).values() for c in v])
cards_dst = sorted([keys.card_plain(c) for c in dst["pool"] + dst["bonus_pool"] + list(dst["claims"].values())]
                   + [keys.card_plain(c) for v in dst["ref_cards"].values() for c in v])
claims_ok = all(keys.card_plain(dst["claims"][keys.mref(code)]) == card and
                keys.machine_plain(dst["claims"][keys.mref(code)]["mct"], keys.mref(code)) == code
                for code, card in (src.get("claims") or {}).items())
pend_ok = all(keys.mref(code) in dst["pending"] for code in (src.get("pending") or {}))
tok_ok = all(dst["ref_tokens"][t] == keys.mref(code) for t, code in (src.get("ref_tokens") or {}).items())
order_ok = [keys.card_plain(c) for c in dst["pool"]] == list(src.get("pool") or [])
report = {"src_leak": v2.leak_scan(src), "dst_leak": v2.leak_scan(dst), "cards": len(cards_src),
          "cards_roundtrip_equal": cards_src == cards_dst, "pool_order_kept": order_ok, "claims": len(dst["claims"]),
          "claims_roundtrip_ok": claims_ok, "pending": len(dst["pending"]), "pending_ok": pend_ok,
          "ref_tokens": len(dst["ref_tokens"]), "ref_tokens_ok": tok_ok, "pool": len(dst["pool"]), "bonus_pool": len(dst["bonus_pool"])}
ok = report["dst_leak"] == {"card_pattern_hits": 0, "machine_code_hits": 0} and all(
    report[k] for k in ("cards_roundtrip_equal", "pool_order_kept", "claims_roundtrip_ok", "pending_ok", "ref_tokens_ok"))
if ok:
    fd = os.open(a.dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(dst, f, ensure_ascii=False, indent=2)
report["upload_renames_needed_at_cutover"] = len(v2.upload_renames(src, keys))
report["written"] = ok
print(json.dumps(report))
sys.exit(0 if ok else 1)
