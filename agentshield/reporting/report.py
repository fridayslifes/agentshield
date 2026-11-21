"""Markdown + HTML report export (HTML is self-contained, no external assets)."""
from __future__ import annotations

import html
from datetime import datetime

import pandas as pd

from .metrics import ORDER, LABEL, asr, asr_by, compare_configs, false_positive_rate


def _md_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "_no data_\n"
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    lines += ["| " + " | ".join(str(v) for v in r) + " |" for r in df.itertuples(index=False)]
    return "\n".join(lines) + "\n"


def build_markdown(df: pd.DataFrame, runs: pd.DataFrame | None = None) -> str:
    out = [f"# AgentShield report\n\nGenerated {datetime.now():%Y-%m-%d %H:%M}.\n"]
    if runs is not None and len(runs):
        r = runs[["id", "config", "mode", "seed", "target_model", "prompt_version", "n_attacks", "api_calls", "status"]]
        out += ["## Reproducibility (stored per run)\n", _md_table(r)]
    out += ["## Before / after: configs A, B, C\n", _md_table(compare_configs(df))]
    for c in [c for c in ORDER if c in set(df["config"])]:
        d = df[df["config"] == c]
        out += [f"## {LABEL[c]}: ASR {asr(d):.1%}, false positives {false_positive_rate(d):.1%}\n",
                "**By category**\n", _md_table(asr_by(d, "category")), "**By severity**\n", _md_table(asr_by(d, "severity"))]
        br = d[(d["verdict"] == "BREACHED") & (~d["benign"])][["attack_id", "category", "severity", "reason"]]
        out += [f"**Breaches ({len(br)})**\n", _md_table(br.head(40))]
    out.append("## Notes\n\nOffline mode measures a *simulated* agent; see README limitations. UNCLEAR verdicts are not counted as breaches.\n")
    return "\n".join(out)


def build_html(df: pd.DataFrame, runs: pd.DataFrame | None = None) -> str:
    cmp_ = compare_configs(df)
    bars = ""
    for c in [c for c in ORDER if c in set(df["config"])]:
        v = asr(df[df["config"] == c]) * 100
        bars += f'<div class="row"><span>{html.escape(LABEL[c])}</span><div class="bar"><i style="width:{v:.1f}%"></i></div><b>{v:.1f}%</b></div>'
    md = build_markdown(df, runs)
    body = html.escape(md)
    table = cmp_.to_html(index=False, border=0) if len(cmp_) else ""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>AgentShield report</title><style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}}
table{{border-collapse:collapse}}td,th{{padding:4px 10px;border-bottom:1px solid #ddd;text-align:left}}
.row{{display:flex;align-items:center;gap:10px;margin:6px 0}}.row span{{width:170px}}
.bar{{flex:1;background:#eee;height:18px;border-radius:4px}}.bar i{{display:block;height:100%;background:#d9534f;border-radius:4px}}
pre{{background:#f6f6f6;padding:1rem;overflow:auto;font-size:12px}}</style></head><body>
<h1>AgentShield report</h1><h2>Attack success rate</h2>{bars}<h2>Comparison</h2>{table}
<h2>Full details (Markdown)</h2><pre>{body}</pre></body></html>"""
