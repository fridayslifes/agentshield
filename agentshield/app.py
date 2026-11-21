"""Streamlit dashboard:  streamlit run agentshield/app.py"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.express as px
import streamlit as st

import os

from agentshield.config import ROOT, apply_mode, load_settings
from agentshield.engine.cost import estimate
from agentshield.engine.defenses import CONFIGS
from agentshield.engine.runner import avg_turns, load_library, prepare_attacks, run_config
from agentshield.llm import LLMError, make_client
from agentshield.reporting.metrics import asr_by, compare_configs, numeric_compare
from agentshield.reporting.report import build_html, build_markdown
from agentshield.storage.db import Database

st.set_page_config(page_title="AgentShield", page_icon="🛡️", layout="wide")
# --- deployment: bridge Streamlit secrets -> env vars (keys never live in the repo) ---
try:
    for _k in ("DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "APP_PASSWORD", "AGENTSHIELD_MODE"):
        if _k in st.secrets and _k not in os.environ:
            os.environ[_k] = str(st.secrets[_k])
except Exception:
    pass

# --- optional password gate so strangers can't spend your API tokens ---
_pw = os.getenv("APP_PASSWORD")
if _pw and not st.session_state.get("authed"):
    st.title("🛡️ AgentShield")
    entered = st.text_input("Password", type="password")
    if entered and entered == _pw:
        st.session_state["authed"] = True
        st.rerun()
    elif entered:
        st.error("Wrong password")
    st.stop()

settings = load_settings()
st.sidebar.title("🛡️ AgentShield")
_modes = ["offline", "deepseek", "anthropic"]
_mode = st.sidebar.selectbox("Backend", _modes, index=_modes.index(settings.mode) if settings.mode in _modes else 0,
                             help="offline = built-in simulator, free, no key. deepseek/anthropic = real model, uses tokens.")
if _mode != "offline":
    _env = "DEEPSEEK_API_KEY" if _mode == "deepseek" else "ANTHROPIC_API_KEY"
    if not os.getenv(_env):
        _k = st.sidebar.text_input(f"{_env}", type="password", help="Kept in this browser session only; never written to disk.")
        if _k:
            os.environ[_env] = _k
    st.sidebar.caption("✅ key found" if os.getenv(_env) else "⚠️ no key yet")
settings = apply_mode(settings, _mode)
db = Database(settings.db_path)
st.sidebar.caption(f"Call cap per run: {settings.call_cap:,}")
page = st.sidebar.radio("Page", ["Overview", "Run", "Results", "Transcript", "Compare", "Report"])
runs = db.runs()


def pick_run(key: str):
    if runs.empty:
        st.info("No runs yet. Go to the Run page first.")
        return None
    labels = {r.id: f"{r.id}  ({r.label}, {r.n_attacks} attacks, {r.status})" for r in runs.itertuples()}
    return st.selectbox("Run", list(labels), format_func=labels.get, key=key)


if page == "Overview":
    st.title("🛡️ AgentShield")
    st.write("How easily can your AI agent be tricked, and does your fix help? Run attacks, then compare configs A, B and C.")
    ids = db.latest_run_per_config()
    if not ids:
        st.info("No runs yet. Open **Run** in the sidebar and press the button; offline mode needs no API key.")
    else:
        df = db.results_df(list(ids.values()))
        cmp_ = numeric_compare(df)
        cols = st.columns(len(cmp_))
        for c, r in zip(cols, cmp_.itertuples()):
            c.metric(r.config, f"{r.asr:.1%} ASR", f"FP {r.false_positive_rate:.1%}", delta_color="off")
        st.plotly_chart(px.bar(cmp_, x="config", y="asr", text_auto=".1%", range_y=[0, 1], title="Attack success rate (lower is better)"))
        st.dataframe(compare_configs(df))
        a = df[(~df["benign"]) & (df["verdict"] == "BREACHED")]
        st.subheader("Most-breached categories")
        st.dataframe(a.groupby(["category", "config"]).size().unstack(fill_value=0))

elif page == "Run":
    st.header("Run attacks")
    cats = sorted({a.category for a in load_library()})
    cfgs = st.multiselect("Defense configs", list(CONFIGS), default=list(CONFIGS), format_func=lambda c: f"{CONFIGS[c].label}: {CONFIGS[c].description}")
    sel = st.multiselect("Categories (empty = all)", cats)
    c1, c2, c3 = st.columns(3)
    max_attacks = c1.slider("Max seed attacks", 5, 74, 74)
    n_gen = c2.slider("Generated attacks (mutators + LLM)", 0, 60, 0)
    seed = c3.number_input("Seed", value=settings.seed, step=1)
    if st.button("Run", type="primary", disabled=not cfgs):
        try:
            llm = make_client(settings)
            attacks = prepare_attacks(settings, llm, categories=sel or None, max_attacks=max_attacks, n_generated=n_gen, seed=int(seed))
        except LLMError as e:
            st.error(str(e))
            st.stop()
        est = estimate(len(attacks) * len(cfgs), avg_turns(attacks), settings)
        st.caption(f"{len(attacks)} attacks x {len(cfgs)} configs | est. calls {est.calls} (cap {est.cap}) | est. cost ${est.usd:.2f}")
        for cfg in cfgs:
            bar, live, rows = st.progress(0.0, text=f"{cfg}..."), st.empty(), []

            def cb(i, n, a, j):
                rows.append({"attack": a.id, "category": a.category, "verdict": j.verdict, "reason": j.reason[:80]})
                bar.progress(i / n, text=f"{cfg}: {i}/{n}")
                live.dataframe(pd.DataFrame(rows).tail(12))

            run_config(cfg, settings, db, attacks, llm=llm, seed=int(seed), progress=cb, categories=sel or None)
        st.success("Done. See Results / Compare.")

elif page == "Results":
    st.header("Results")
    rid = pick_run("res_run")
    if rid:
        df = db.results_df([rid])
        a = df[~df["benign"]]
        st.metric("Attack success rate", f"{(a['verdict'] == 'BREACHED').mean():.1%}", help="BREACHED / all non-benign attacks")
        c1, c2 = st.columns(2)
        c1.plotly_chart(px.bar(asr_by(df, "category"), x="category", y="asr", title="ASR by category", range_y=[0, 1]))
        c2.plotly_chart(px.bar(asr_by(df, "severity"), x="severity", y="asr", title="ASR by severity", range_y=[0, 1]))
        f1, f2 = st.columns(2)
        fc = f1.multiselect("Category", sorted(df["category"].unique()))
        fv = f2.multiselect("Verdict", ["BREACHED", "BLOCKED", "UNCLEAR", "PASSED"], default=["BREACHED"])
        t = df[df["verdict"].isin(fv)]
        if fc:
            t = t[t["category"].isin(fc)]
        st.dataframe(t[["result_id", "attack_id", "category", "severity", "verdict", "method", "reason"]])

elif page == "Transcript":
    st.header("Transcript viewer")
    rid = pick_run("tr_run")
    if rid:
        df = db.results_df([rid])
        rr = st.selectbox("Attempt", df["result_id"], format_func=lambda i: f"#{i}  {df.set_index('result_id').loc[i, 'attack_id']}  [{df.set_index('result_id').loc[i, 'verdict']}]")
        data = db.transcript(int(rr))
        for ev in json.loads(data["result"]["transcript"])["events"]:
            k = ev["kind"]
            if k == "user":
                st.chat_message("user").write(ev["content"])
            elif k == "assistant":
                st.chat_message("assistant").write(ev["content"])
            elif k == "tool_call":
                st.code(f"CALL {ev['content']}({json.dumps(ev['data'].get('args'))})", language="text")
            elif k == "tool_result":
                st.code(f"RESULT (executed={ev['data'].get('executed')}): {ev['content']}", language="text")
            else:
                st.warning(f"Filter [{ev['data'].get('where')}]: {ev['content']}")
        j = data["judgment"]
        st.subheader(f"Judge: {j['verdict']} (confidence {j['confidence']:.2f}, via {j['method']})")
        st.write(j["reason"])
        if j["evidence_quote"]:
            st.code(j["evidence_quote"], language="text")

elif page == "Compare":
    st.header("Before / after: A vs B vs C")
    ids = db.latest_run_per_config()
    if not ids:
        st.info("Run at least one config first.")
    else:
        df = db.results_df(list(ids.values()))
        st.dataframe(compare_configs(df))
        n = numeric_compare(df)
        st.plotly_chart(px.bar(n.melt("config"), x="config", y="value", color="variable", barmode="group", range_y=[0, 1],
                               title="Attack success rate and false-positive rate (benign controls)"))
        st.caption("Uses the most recent run of each config. For a fair comparison run all three with the same seed and attack count.")

elif page == "Report":
    st.header("Export report")
    ids = db.latest_run_per_config()
    if not ids:
        st.info("Run at least one config first.")
    else:
        df = db.results_df(list(ids.values()))
        rs = runs[runs["id"].isin(ids.values())]
        md, html_ = build_markdown(df, rs), build_html(df, rs)
        (ROOT / "reports").mkdir(exist_ok=True)
        (ROOT / "reports" / "report.md").write_text(md)
        (ROOT / "reports" / "report.html").write_text(html_)
        c1, c2 = st.columns(2)
        c1.download_button("Download Markdown", md, "agentshield_report.md", "text/markdown")
        c2.download_button("Download HTML", html_, "agentshield_report.html", "text/html")
        st.caption("Also saved to ./reports/")
        st.markdown(md)
