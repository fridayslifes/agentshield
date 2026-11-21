"""LLM client abstraction: a real Anthropic client and the offline simulator share one interface.

Internal message format (plain dicts):
  {"role": "user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id","name","args"}]}
  {"role": "tool", "name": str, "call_id": str, "content": str}
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class LLMError(RuntimeError):
    """Raised with a human-readable message when the LLM backend fails."""


class BudgetExceeded(LLMError):
    """Raised when the per-run call cap is reached."""


@dataclass
class ToolCallReq:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCallReq] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


class CallBudget:
    """Counts LLM calls and enforces the cost cap."""

    def __init__(self, limit: int):
        self.limit, self.used = limit, 0
        self.input_tokens = self.output_tokens = 0

    def charge(self) -> None:
        if self.used >= self.limit:
            raise BudgetExceeded(f"API call cap reached ({self.limit}). Raise max_api_calls in config.yaml.")
        self.used += 1

    def add_tokens(self, i: int, o: int) -> None:
        self.input_tokens += i
        self.output_tokens += o


class LLMClient(ABC):
    name = "abstract"

    def __init__(self, budget: CallBudget | None = None):
        self.budget = budget or CallBudget(10**9)

    @abstractmethod
    def chat(self, system: str, messages: list[dict], tools: list[dict], model: str, seed: int = 0) -> LLMResponse: ...

    @abstractmethod
    def complete_text(self, system: str, prompt: str, model: str, seed: int = 0) -> str: ...


class AnthropicLLM(LLMClient):
    """Real Claude API backend. Needs ANTHROPIC_API_KEY. Never used in offline mode."""

    name = "anthropic"

    def __init__(self, budget: CallBudget | None = None):
        super().__init__(budget)
        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise LLMError("ANTHROPIC_API_KEY is not set. Use AGENTSHIELD_MODE=offline, or export the key.")
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise LLMError("pip install anthropic to use anthropic mode") from e
        self._a = anthropic
        self.client = anthropic.Anthropic(api_key=key, timeout=60.0)

    def _retry(self, fn):
        a = self._a
        retryable = (a.RateLimitError, a.APITimeoutError, a.APIConnectionError, a.InternalServerError)
        for attempt in range(4):
            try:
                return fn()
            except retryable as e:
                if attempt == 3:
                    raise LLMError(f"Anthropic API failed after retries: {e}") from e
                time.sleep(2**attempt)
            except a.APIStatusError as e:
                raise LLMError(f"Anthropic API error {e.status_code}: {e}") from e

    @staticmethod
    def _to_api(messages: list[dict]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                blocks: list[dict] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls", []):
                    blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["args"]})
                out.append({"role": "assistant", "content": blocks})
            else:
                block = {"type": "tool_result", "tool_use_id": m["call_id"], "content": m["content"]}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    def chat(self, system, messages, tools, model, seed=0) -> LLMResponse:
        self.budget.charge()
        kwargs: dict[str, Any] = dict(model=model, max_tokens=1000, system=system, messages=self._to_api(messages))
        if tools:
            kwargs["tools"] = tools
        r = self._retry(lambda: self.client.messages.create(**kwargs))
        text = "".join(b.text for b in r.content if b.type == "text")
        calls = [ToolCallReq(b.id, b.name, dict(b.input)) for b in r.content if b.type == "tool_use"]
        self.budget.add_tokens(r.usage.input_tokens, r.usage.output_tokens)
        return LLMResponse(text, calls, r.usage.input_tokens, r.usage.output_tokens)

    def complete_text(self, system, prompt, model, seed=0) -> str:
        r = self.chat(system, [{"role": "user", "content": prompt}], [], model, seed)
        return r.text


class DeepSeekLLM(LLMClient):
    """DeepSeek backend (any OpenAI-compatible chat endpoint).

    Works with api.deepseek.com and with OpenAI-compatible gateways/proxies: set
    DEEPSEEK_BASE_URL to either the base (https://host/v1) or the full
    (.../v1/chat/completions) URL. The key comes from DEEPSEEK_API_KEY, never from code.
    """

    name = "deepseek"
    URL = "https://api.deepseek.com/chat/completions"

    def __init__(self, budget: CallBudget | None = None):
        super().__init__(budget)
        self.key = os.getenv("DEEPSEEK_API_KEY")
        if not self.key:
            raise LLMError("DEEPSEEK_API_KEY is not set. Export it (or put it in .env), or use AGENTSHIELD_MODE=offline.")
        self.url = self._normalise(os.getenv("DEEPSEEK_BASE_URL") or self.URL)

    @staticmethod
    def _normalise(url: str) -> str:
        """Accept a bare base URL, a /v1 base, or a full chat/completions URL."""
        url = url.strip().rstrip("/")
        if url.endswith("/chat/completions"):
            return url
        if url.endswith("/v1"):
            return url + "/chat/completions"
        return url + "/v1/chat/completions"

    @staticmethod
    def _to_api(system: str, messages: list[dict]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                d: dict[str, Any] = {"role": "assistant", "content": m.get("content") or ""}
                if m.get("tool_calls"):
                    d["tool_calls"] = [{"id": t["id"], "type": "function",
                                        "function": {"name": t["name"], "arguments": json.dumps(t["args"])}} for t in m["tool_calls"]]
                out.append(d)
            else:
                out.append({"role": "tool", "tool_call_id": m["call_id"], "content": m["content"]})
        return out

    def _post(self, body: dict) -> dict:
        # Some OpenAI-compatible gateways sit behind Cloudflare and reject the default
        # Python-urllib User-Agent with "error code: 1010". Send an explicit UA.
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.key}",
            "Accept": "application/json",
            "User-Agent": os.getenv("DEEPSEEK_USER_AGENT", "agentshield/1.0 (+https://github.com)"),
        }
        data = json.dumps(body).encode()
        for attempt in range(4):
            req = urllib.request.Request(self.url, data=data, method="POST", headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503) and attempt < 3:
                    time.sleep(2**attempt)
                    continue
                raise LLMError(f"DeepSeek API error {e.code}: {e.read()[:200]!r}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt == 3:
                    raise LLMError(f"DeepSeek API unreachable after retries: {e}") from e
                time.sleep(2**attempt)
        raise LLMError("DeepSeek API failed")

    def chat(self, system, messages, tools, model, seed=0) -> LLMResponse:
        self.budget.charge()
        body: dict[str, Any] = {"model": model, "messages": self._to_api(system, messages), "max_tokens": 1000}
        if tools:
            body["tools"] = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                              "parameters": t["input_schema"]}} for t in tools]
        msg = self._post(body)
        m = msg["choices"][0]["message"]
        calls = [ToolCallReq(c["id"], c["function"]["name"], json.loads(c["function"]["arguments"] or "{}")) for c in m.get("tool_calls") or []]
        u = msg.get("usage", {})
        self.budget.add_tokens(u.get("prompt_tokens", 0), u.get("completion_tokens", 0))
        return LLMResponse(m.get("content") or "", calls, u.get("prompt_tokens", 0), u.get("completion_tokens", 0))

    def complete_text(self, system, prompt, model, seed=0) -> str:
        return self.chat(system, [{"role": "user", "content": prompt}], [], model, seed).text


def make_client(settings, budget: CallBudget | None = None) -> LLMClient:
    """Factory: offline simulator by default, real API only when explicitly enabled."""
    budget = budget or CallBudget(settings.call_cap)
    if settings.mode == "anthropic":
        return AnthropicLLM(budget)
    if settings.mode == "deepseek":
        return DeepSeekLLM(budget)
    from .sim import SimulatedLLM

    return SimulatedLLM(budget)
