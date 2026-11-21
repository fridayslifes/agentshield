"""Settings loader: config.yaml + .env + environment overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PKG = Path(__file__).resolve().parent


def _load_env(path: Path) -> None:
    """Load KEY=VALUE lines from .env (python-dotenv if present, else a tiny parser)."""
    if not path.exists():
        return
    try:
        from dotenv import load_dotenv

        load_dotenv(path)
        return
    except ImportError:
        pass
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


@dataclass
class Settings:
    mode: str = "offline"
    target_model: str = "claude-sonnet-5-5"
    judge_model: str = "claude-sonnet-5-5"
    attack_model: str = "claude-haiku-5-5"
    max_api_calls: int = 500
    offline_max_calls: int = 100000
    seed: int = 1337
    db_path: str = "agentshield.db"
    prices: dict = field(default_factory=dict)

    @property
    def call_cap(self) -> int:
        return self.offline_max_calls if self.mode == "offline" else self.max_api_calls


def load_settings(path: Path | None = None) -> Settings:
    _load_env(ROOT / ".env")
    raw = {}
    cfg = path or ROOT / "config.yaml"
    if Path(cfg).exists():
        raw = yaml.safe_load(Path(cfg).read_text()) or {}
    models = raw.get("models", {})
    s = Settings(
        mode=os.getenv("AGENTSHIELD_MODE", raw.get("mode", "offline")),
        target_model=os.getenv("TARGET_MODEL", models.get("target", "claude-sonnet-5-5")),
        judge_model=os.getenv("JUDGE_MODEL", models.get("judge", "claude-sonnet-5-5")),
        attack_model=os.getenv("ATTACK_MODEL", models.get("attacker", "claude-haiku-5-5")),
        max_api_calls=int(raw.get("max_api_calls", 500)),
        offline_max_calls=int(raw.get("offline_max_calls", 100000)),
        seed=int(raw.get("seed", 1337)),
        db_path=str(raw.get("db_path", "agentshield.db")),
        prices=raw.get("prices_per_mtok", {}),
    )
    if s.mode == "deepseek":  # sensible defaults unless overridden by env / config.yaml
        d = raw.get("deepseek", {}) or {}
        model = os.getenv("TARGET_MODEL") or d.get("model") or "deepseek-chat"
        s.target_model = os.getenv("TARGET_MODEL") or d.get("target") or model
        s.judge_model = os.getenv("JUDGE_MODEL") or d.get("judge") or model
        s.attack_model = os.getenv("ATTACK_MODEL") or d.get("attacker") or model
        if d.get("base_url") and not os.getenv("DEEPSEEK_BASE_URL"):
            os.environ["DEEPSEEK_BASE_URL"] = str(d["base_url"])
        s.prices = {s.target_model: list(d.get("price_per_mtok", [0.27, 1.10])), **s.prices}
    if not Path(s.db_path).is_absolute():
        s.db_path = str(ROOT / s.db_path)
    return s


def apply_mode(s: Settings, mode: str) -> Settings:
    """Switch backend at runtime (used by the dashboard sidebar)."""
    s.mode = mode
    if mode == "deepseek":
        # Model names come from env (or the config.yaml deepseek block); never hard-code one
        # that a given gateway may not serve.
        model = os.getenv("TARGET_MODEL") or os.getenv("DEEPSEEK_MODEL") or s.target_model
        if model.startswith("claude-"):
            model = "deepseek-chat"
        s.target_model = os.getenv("TARGET_MODEL") or model
        s.judge_model = os.getenv("JUDGE_MODEL") or model
        s.attack_model = os.getenv("ATTACK_MODEL") or model
        s.prices = {s.target_model: [0.27, 1.10], **s.prices}
    elif mode == "anthropic":
        s.target_model, s.judge_model, s.attack_model = "claude-sonnet-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"
    return s
