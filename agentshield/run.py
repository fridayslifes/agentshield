"""CLI:  python -m agentshield.run --config baseline"""
from __future__ import annotations

import argparse
import sys

from .config import load_settings
from .engine.cost import estimate
from .engine.defenses import CONFIGS, get_config
from .engine.runner import avg_turns, prepare_attacks, run_config
from .llm import LLMError, make_client
from .reporting.metrics import compare_configs
from .storage.db import Database


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentshield.run", description="Red-team the bundled demo agent.")
    ap.add_argument("--config", default="baseline", help="baseline|hardened|hardened_filters (or A/B/C, or 'all')")
    ap.add_argument("--categories", nargs="*", help="limit to these categories")
    ap.add_argument("--max-attacks", type=int, help="cap the number of seed attacks")
    ap.add_argument("--generated", type=int, default=0, help="extra mutated / LLM-generated attacks")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--yes", action="store_true", help="skip the cost confirmation prompt")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    s = load_settings()
    try:
        llm = make_client(s)
        names = list(CONFIGS) if args.config.lower() == "all" else [get_config(args.config).name]
        attacks = prepare_attacks(s, llm, categories=args.categories, max_attacks=args.max_attacks, n_generated=args.generated, seed=args.seed)
    except (LLMError, KeyError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    est = estimate(len(attacks) * len(names), avg_turns(attacks), s)
    print(f"Mode: {s.mode} | attacks: {len(attacks)} x {len(names)} config(s) | est. calls: {est.calls} (cap {est.cap}/run) | "
          f"est. tokens: {est.input_tokens:,} in / {est.output_tokens:,} out | est. cost: ${est.usd:.2f}")
    if s.mode != "offline" and not args.yes and input("Proceed? [y/N] ").lower() != "y":
        return 1
    db = Database(s.db_path)

    def show(i, n, a, j):
        if not args.quiet:
            print(f"  [{i:>3}/{n}] {j.verdict:<8} {a.id:<14} {a.severity:<6} {j.reason[:70]}")

    ids = {}
    for name in names:
        print(f"\n=== config: {name} ({get_config(name).description}) ===")
        ids[name] = run_config(name, s, db, attacks, llm=llm, seed=args.seed, progress=show)
    df = db.results_df(list(ids.values()))
    print("\n" + compare_configs(df).to_string(index=False))
    print(f"\nStored in {s.db_path}. Open the dashboard: streamlit run agentshield/app.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
