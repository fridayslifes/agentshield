"""Tool-using agent loop. Works with any LLMClient (simulated or real)."""
from __future__ import annotations

from ..engine.defenses import Defenses
from ..llm import LLMClient
from ..models import Event, ToolCallRecord, Transcript
from .tools import TOOL_SCHEMAS, ToolBox


class Agent:
    def __init__(self, llm: LLMClient, system_prompt: str, model: str, seed: int = 0,
                 defenses: Defenses | None = None, toolbox: ToolBox | None = None, max_steps: int = 5):
        self.llm, self.system, self.model, self.seed = llm, system_prompt, model, seed
        self.defenses = defenses or Defenses(system_prompt=system_prompt)
        self.toolbox = toolbox or ToolBox()
        self.max_steps = max_steps
        self.messages: list[dict] = []
        self.transcript = Transcript()

    def _log(self, kind: str, content: str = "", **data) -> None:
        self.transcript.events.append(Event(kind=kind, content=content, data=data))

    def _reply(self, text: str) -> str:
        self.transcript.outputs.append(text)
        self._log("assistant", text)
        self.messages.append({"role": "assistant", "content": text})
        return text

    def run_turn(self, user_text: str, inject: dict[str, str] | None = None) -> str:
        """Process one user message; returns the final assistant reply."""
        self._log("user", user_text)
        reason = self.defenses.check_input(user_text)
        if reason:
            self._log("filter", reason, where="input")
            self.messages.append({"role": "user", "content": "[message blocked by input filter]"})
            return self._reply("Request blocked by the input filter.")
        self.messages.append({"role": "user", "content": user_text})

        for _ in range(self.max_steps):
            resp = self.llm.chat(self.system, self.messages, TOOL_SCHEMAS, self.model, self.seed)
            if not resp.tool_calls:
                clean = self.defenses.filter_output(resp.text)
                if clean != resp.text:
                    self._log("filter", "output redacted", where="output")
                return self._reply(clean)
            self.messages.append({"role": "assistant", "content": resp.text,
                                  "tool_calls": [{"id": c.id, "name": c.name, "args": c.args} for c in resp.tool_calls]})
            for call in resp.tool_calls:
                self._log("tool_call", call.name, args=call.args)
                denied = self.defenses.check_tool(call.name, call.args)
                if denied:
                    rec = ToolCallRecord(name=call.name, args=call.args, result=f"Error: {denied}", executed=False, blocked_reason=denied)
                else:
                    rec = self.toolbox.execute(call.name, call.args, inject)
                    rec.result = self.defenses.sanitize_tool_output(rec.result)
                self.transcript.tool_calls.append(rec)
                self._log("tool_result", rec.result, name=call.name, executed=rec.executed)
                self.messages.append({"role": "tool", "name": call.name, "call_id": call.id, "content": rec.result})
        return self._reply("[stopped: maximum tool steps reached]")
