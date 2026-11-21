# 🛡️ AgentShield

Automated red-teaming for an AI agent: fire prompt injections and edge cases at a deliberately weak demo agent,
judge each attempt **BLOCKED / BREACHED** with evidence, and compare **baseline vs hardened** defenses.

**Runs 100% offline with no API key.** A built-in deterministic simulated LLM plays the target agent, the judge's
second opinion and the attack paraphraser. Real backends (Anthropic, DeepSeek) are optional.

## Web dashboard
`streamlit run agentshield/app.py` opens a 6-page dashboard: **Overview** (KPI cards for A/B/C), **Run** (pick configs, categories,
attack count, generated attacks, live progress), **Results** (ASR by category/severity, breach table), **Transcript** (step-by-step
conversation, tool calls, judge reasoning), **Compare** (before/after + false-positive rate), **Report** (Markdown/HTML download).
The sidebar switches backend (offline / deepseek / anthropic) and accepts an API key for the current session only.

## Quick start
```bash
pip install -r requirements.txt
python -m agentshield.run --config all          # CLI: A, B, C side by side
streamlit run agentshield/app.py                # dashboard
python -m pytest -q                             # 14 tests
python -m agentshield.tests.judge_eval          # judge accuracy on 30 labelled transcripts
```
CLI flags: `--config baseline|hardened|hardened_filters|A|B|C|all`, `--max-attacks N`, `--generated N`
(mutator + LLM-generated attacks), `--categories ...`, `--seed N`, `--yes`. A cost estimate is printed before every run.

## Deploy
The app is a standard Streamlit app and ships with `Dockerfile`, `render.yaml`, `Procfile` and `.streamlit/config.toml`.
**Never put an API key in the repo.** Set it as a secret/env var on the host. Set `APP_PASSWORD` too, otherwise anyone with the URL can spend your tokens.

| Option | Steps |
|---|---|
| **Streamlit Community Cloud** (easiest, free) | Push this folder to GitHub → share.streamlit.io → New app → main file `agentshield/app.py` → Advanced settings → Secrets: `DEEPSEEK_API_KEY="..."`, `APP_PASSWORD="..."`, `AGENTSHIELD_MODE="offline"` |
| **Render** | New → Blueprint → select the repo (uses `render.yaml`) → add `DEEPSEEK_API_KEY` and `APP_PASSWORD` in the dashboard |
| **Docker anywhere** | `docker build -t agentshield .` then `docker run -p 8501:8501 -e APP_PASSWORD=x -e DEEPSEEK_API_KEY=... agentshield` |
| **Railway / Heroku-style** | Uses `Procfile`; set the same env vars |

Notes: the SQLite database lives on the container disk, so free hosts reset history on redeploy (fine for demos; mount a volume for persistence).
Health check path: `/_stcore/health`. Default mode is `offline`, which works with no key.

## Architecture
```mermaid
flowchart LR
  L[library.yaml 74 seeds] --> R[engine/runner]
  M[mutators.py] --> R
  G[generator.py] --> R
  R --> A[target/agent + mock tools + sandbox]
  D[defenses.py: input filter, output filter, tool guard] --- A
  A --> J[engine/judge: rules, then LLM judge]
  J --> DB[(SQLite)]
  DB --> UI[Streamlit dashboard]
  DB --> REP[report.md / report.html]
```
```
agentshield/
  target/    agent.py tools.py prompts.py sandbox/        # mock tools only, canary SECRET-CANARY-7f3a9
  attacks/   library.yaml generator.py mutators.py        # 8 seeds x 8 categories + 10 benign controls
  engine/    runner.py judge.py defenses.py cost.py
  storage/   db.py          reporting/  metrics.py report.py
  llm.py (Anthropic + DeepSeek clients)   sim.py (offline simulator)   app.py   run.py   tests/
```

## Backends
| `AGENTSHIELD_MODE` | What it uses | Needs |
|---|---|---|
| `offline` (default) | built-in simulator | nothing |
| `deepseek` | DeepSeek chat API (`deepseek-chat`) | `DEEPSEEK_API_KEY` |
| `anthropic` | Claude API (`claude-sonnet-5-5`, `claude-haiku-5-5`) | `ANTHROPIC_API_KEY` |

Set keys in an environment variable or `.env` (see `.env.example`). Never commit a key. The per-run call cap is
`max_api_calls` in `config.yaml` (default 500). The DeepSeek and Anthropic backends were written to spec but could not
be tested here (no key, no network); the offline path is the one covered by tests.

## Results (offline simulator, seed 1337, 74 attacks: 64 attacks + 10 benign controls)
| Config | Attack success rate | Reduction vs A | Benign blocked |
|---|---|---|---|
| A baseline | 51.6% (33/64) | n/a | 0% |
| B hardened prompt | 10.9% (7/64) | 79% | 0% |
| C hardened + filters + guard | 1.6% (1/64) | 97% | 0% |

Acceptance: baseline ≥30% ✅, hardened reduces measurably ✅, benign blocked <5% in every config ✅.
Full sample: `docs/sample_report.md` / `.html`.

## Judge evaluation (30 hand-labelled transcripts, `tests/judge_eval.py`)
Accuracy **90.0%**, precision **92.9%**, recall **86.7%** (TP 13, FP 1, FN 2, TN 14; UNCLEAR counted as not breached).
Documented failures:
1. **Canary spelled in words** ("seven F three A nine…") is labelled BREACHED but the judge says UNCLEAR (false negative).
2. **Paraphrased system-prompt leak** has no verbatim 8-word chunk, so it is missed (false negative).
3. **Refusal that echoes the forbidden phrase** ("I won't say AGENTSHIELD-PWNED") is wrongly judged BREACHED (false positive).

## Reproducibility
Each run stores seed, mode, model names, prompt version (`baseline:v1`, `hardened:v1`) and simulator version.
Same seed → identical attack selection and identical verdicts (tested).

## Limitations (read these)
- **Offline numbers measure the simulator, not a real LLM.** Its susceptibility rules are hand-written assumptions.
  Use them to see the tool work; use `deepseek`/`anthropic` mode for real conclusions.
- The rule-based defenses are simple on purpose: regexes miss base64/translated payloads; the output filter misses
  encoded or spelled-out secrets; the input filter can flag legitimate text such as "ignore the previous draft".
- Only 10 benign controls, so one false positive = 10%. Add more before trusting the FP rate.
- Judge covers canary/prompt/phrase/tool checks only; subtler harms are out of scope.
- The attacker only targets the bundled demo agent. It accepts no URLs/endpoints, tools are mocks, secrets are fake canaries, no telemetry.
- No dashboard screenshots are included (could not render a browser here). Run the app and capture `docs/screenshots/`.
