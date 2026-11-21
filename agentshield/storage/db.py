"""SQLite storage: runs, attacks, results, judgments."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, created_at TEXT, config TEXT, label TEXT, mode TEXT, seed INTEGER,
  target_model TEXT, judge_model TEXT, attack_model TEXT, prompt_version TEXT, sim_version TEXT, n_attacks INTEGER,
  n_generated INTEGER, categories TEXT, api_calls INTEGER DEFAULT 0, status TEXT DEFAULT 'running');
CREATE TABLE IF NOT EXISTS attacks(run_id TEXT, id TEXT, category TEXT, severity TEXT, goal TEXT, success_check TEXT,
  benign INTEGER, mutation TEXT, parent TEXT, body TEXT, PRIMARY KEY(run_id, id));
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, attack_id TEXT, transcript TEXT,
  output TEXT, tool_calls TEXT, error TEXT, duration REAL);
CREATE TABLE IF NOT EXISTS judgments(result_id INTEGER PRIMARY KEY, verdict TEXT, reason TEXT, evidence_quote TEXT,
  confidence REAL, method TEXT);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.con = sqlite3.connect(self.path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)

    def create_run(self, run_id: str, **f) -> None:
        f.setdefault("created_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        cols = ",".join(["id", *f]); q = ",".join("?" * (len(f) + 1))
        self.con.execute(f"INSERT INTO runs({cols}) VALUES({q})", [run_id, *f.values()])
        self.con.commit()

    def finish_run(self, run_id: str, api_calls: int, status: str) -> None:
        self.con.execute("UPDATE runs SET api_calls=?, status=? WHERE id=?", (api_calls, status, run_id))
        self.con.commit()

    def save_attack(self, run_id: str, a) -> None:
        self.con.execute("INSERT OR REPLACE INTO attacks VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (run_id, a.id, a.category, a.severity, a.goal, a.success_check, int(a.benign), a.mutation, a.parent, a.model_dump_json()))

    def save_result(self, run_id: str, attack_id: str, transcript, error: str | None, duration: float) -> int:
        cur = self.con.execute("INSERT INTO results(run_id,attack_id,transcript,output,tool_calls,error,duration) VALUES(?,?,?,?,?,?,?)",
                               (run_id, attack_id, transcript.model_dump_json(), transcript.final_output,
                                json.dumps([c.model_dump() for c in transcript.tool_calls]), error, duration))
        return int(cur.lastrowid)

    def save_judgment(self, result_id: int, j) -> None:
        self.con.execute("INSERT OR REPLACE INTO judgments VALUES(?,?,?,?,?,?)",
                         (result_id, j.verdict, j.reason, j.evidence_quote, j.confidence, j.method))
        self.con.commit()

    def runs(self) -> pd.DataFrame:
        return pd.read_sql_query("SELECT * FROM runs ORDER BY created_at DESC, rowid DESC", self.con)

    def results_df(self, run_ids: list[str] | None = None) -> pd.DataFrame:
        q = """SELECT r.id AS result_id, r.run_id, ru.config, ru.label, a.id AS attack_id, a.category, a.severity, a.benign,
               a.mutation, a.goal, j.verdict, j.reason, j.evidence_quote, j.confidence, j.method, r.error
               FROM results r JOIN attacks a ON a.run_id=r.run_id AND a.id=r.attack_id
               JOIN runs ru ON ru.id=r.run_id LEFT JOIN judgments j ON j.result_id=r.id"""
        params: list = []
        if run_ids:
            q += f" WHERE r.run_id IN ({','.join('?' * len(run_ids))})"
            params = list(run_ids)
        df = pd.read_sql_query(q + " ORDER BY r.id", self.con, params=params)
        df["benign"] = df["benign"].astype(bool)
        return df

    def transcript(self, result_id: int) -> dict:
        row = self.con.execute("SELECT * FROM results WHERE id=?", (result_id,)).fetchone()
        j = self.con.execute("SELECT * FROM judgments WHERE result_id=?", (result_id,)).fetchone()
        return {"result": dict(row), "judgment": dict(j) if j else None}

    def latest_run_per_config(self) -> dict[str, str]:
        df = self.runs()
        df = df[df["status"].isin(["complete", "partial"])]
        return {c: g.iloc[0]["id"] for c, g in df.groupby("config")}
