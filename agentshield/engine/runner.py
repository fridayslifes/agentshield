"""Runs attacks against a target config (single and multi-turn), judges and stores each attempt."""
from __future__ import annotations

import random
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import yaml

from ..attacks.generator import AttackGenerator
from ..attacks.mutators import mutate_all
from ..config import PKG, Settings
from ..llm import BudgetExceeded, CallBudget, LLMClient, LLMError, make_client
from ..models import Attack, Judgment, Transcript
from ..storage.db import Database
from ..target.agent import Agent
from .defenses import ConfigSpec, get_config
from .judge import judge

LIBRARY = PKG / "attacks" / "library.yaml"
Progress = Callable[[int, int, Attack, Judgment], None]


def load_library(path: Path | None = None) -> list[Attack]:
    return [Attack(**d) for d in yaml.safe_load(Path(path or LIBRARY).read_text())]


def prepare_attacks(settings: Settings, llm: LLMClient, *, categories: Optional[list[str]] = None, max_attacks: Optional[int] = None,
                    n_generated: int = 0, seed: Optional[int] = None) -> list[Attack]:
    """Pick the attack list once so configs A/B/C are compared on identical inputs."""
    seed = settings.seed if seed is None else seed
    pool = [a for a in load_library() if not categories or a.category in categories]
    rng = random.Random(seed)
    sel = pool[:]
    rng.shuffle(sel)
    if max_attacks:
        sel = sel[:max_attacks]
    extra: list[Attack] = []
    if n_generated:
        seeds = [a for a in sel if not a.benign]
        half = n_generated // 2
        rules = mutate_all(seeds)
        rng.shuffle(rules)
        extra += rules[: n_generated - half]
        extra += AttackGenerator(llm, settings.attack_model, seed).generate(seeds, half)
    return sorted(sel, key=lambda a: a.id) + extra


def avg_turns(attacks: list[Attack]) -> float:
    return sum(len(a.turns) for a in attacks) / max(len(attacks), 1)


def run_attack(attack: Attack, cfg: ConfigSpec, llm: LLMClient, model: str, seed: int) -> Transcript:
    agent = Agent(llm, cfg.system_prompt, model, seed, cfg.build_defenses())
    for text, inject in attack.user_turns():
        agent.run_turn(text, inject)
    return agent.transcript


def run_config(config: str, settings: Settings, db: Database, attacks: list[Attack], *, llm: Optional[LLMClient] = None,
               seed: Optional[int] = None, progress: Optional[Progress] = None, categories: Optional[list[str]] = None) -> str:
    cfg = get_config(config)
    seed = settings.seed if seed is None else seed
    llm = llm or make_client(settings)
    llm.budget = CallBudget(settings.call_cap)  # fresh cap per run
    run_id = f"{cfg.name}-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"
    db.create_run(run_id, config=cfg.name, label=cfg.label, mode=settings.mode, seed=seed, target_model=settings.target_model,
                  judge_model=settings.judge_model, attack_model=settings.attack_model, prompt_version=cfg.prompt_version,
                  sim_version="sim-v1" if settings.mode == "offline" else "n/a", n_attacks=len(attacks),
                  n_generated=sum(a.mutation is not None for a in attacks), categories=",".join(categories or []))
    status = "complete"
    for i, a in enumerate(attacks, 1):
        db.save_attack(run_id, a)
        t0, err = time.time(), None
        try:
            tr = run_attack(a, cfg, llm, settings.target_model, seed)
            j = judge(a, tr, cfg.system_prompt, llm, settings.judge_model)
        except BudgetExceeded as e:
            err, status = str(e), "partial"
            db.finish_run(run_id, llm.budget.used, status)
            print(f"[!] {e} Stopping after {i - 1}/{len(attacks)} attacks.")
            break
        except LLMError as e:  # API failure on one attack should not kill the run
            tr, err = Transcript(), str(e)
            j = Judgment(verdict="UNCLEAR", reason=f"error: {e}", method="rule")
        rid = db.save_result(run_id, a.id, tr, err, time.time() - t0)
        db.save_judgment(rid, j)
        if progress:
            progress(i, len(attacks), a, j)
    db.finish_run(run_id, llm.budget.used, status)
    return run_id
