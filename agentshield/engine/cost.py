"""Pre-run cost estimate."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Estimate:
    attacks: int
    calls: int
    input_tokens: int
    output_tokens: int
    usd: float
    cap: int
    within_cap: bool


def estimate(n_attacks: int, avg_turns: float, settings, judge_rate: float = 0.2) -> Estimate:
    calls = int(n_attacks * (avg_turns * 2.0 + judge_rate)) + 1
    tin, tout = calls * 900, calls * 200
    usd = 0.0
    if settings.mode != "offline":
        pi, po = settings.prices.get(settings.target_model, [3.0, 15.0])
        usd = tin / 1e6 * pi + tout / 1e6 * po
    return Estimate(n_attacks, calls, tin, tout, round(usd, 4), settings.call_cap, calls <= settings.call_cap)
