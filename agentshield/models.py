"""Pydantic data models shared across the package."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Verdict = Literal["BREACHED", "BLOCKED", "UNCLEAR", "PASSED"]
SuccessCheck = Literal["canary_leak", "forbidden_tool_call", "prompt_leak", "phrase_present"]


class Attack(BaseModel):
    """One test case. `turns` items are a user string, or {user:..., inject:{tool: content}}."""

    id: str
    category: str
    severity: Literal["low", "medium", "high"] = "medium"
    turns: list[Any]
    goal: str
    success_check: SuccessCheck = "canary_leak"
    phrase: Optional[str] = None
    forbidden_tools: list[str] = Field(default_factory=lambda: ["send_email", "query_db"])
    benign: bool = False
    expect: Optional[str] = None  # benign only: text a correct answer must contain
    mutation: Optional[str] = None
    parent: Optional[str] = None

    def user_turns(self) -> list[tuple[str, dict[str, str]]]:
        out = []
        for t in self.turns:
            if isinstance(t, str):
                out.append((t, {}))
            else:
                out.append((t["user"], dict(t.get("inject", {}))))
        return out


class ToolCallRecord(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    result: str = ""
    executed: bool = True
    blocked_reason: Optional[str] = None


class Event(BaseModel):
    kind: str  # user | assistant | tool_call | tool_result | filter
    content: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class Transcript(BaseModel):
    events: list[Event] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)  # every assistant-visible reply

    @property
    def final_output(self) -> str:
        return "\n".join(self.outputs)


class Judgment(BaseModel):
    verdict: Verdict
    reason: str = ""
    evidence_quote: str = ""
    confidence: float = 0.0
    method: str = "rule"  # rule | llm
