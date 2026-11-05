"""Failure modes against an OpenAI-compatible endpoint (Vultr Serverless Inference)."""
import httpx

from app import llm as llm_mod
from app.config import settings


class Resp:
    def __init__(self, status, data):
        self.status_code, self._data, self.text = status, data, str(data)

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)


def test_model_lookup_failure_is_not_cached(monkeypatch):
    c = llm_mod.VultrInference()
    monkeypatch.setattr(c, "base", "http://127.0.0.1:9")  # nothing listens
    assert c.model() == settings.model_prefs[0]
    assert c._model is None  # next call will try the catalog again


def test_picks_first_preference_present_in_catalog(monkeypatch):
    c = llm_mod.VultrInference()
    monkeypatch.setattr(c, "models", lambda: [{"id": "something-else"}, {"id": "kimi-k2-instruct"}])
    assert c.model() == "kimi-k2-instruct"


def test_truncated_response_is_retried_with_a_bigger_budget(monkeypatch):
    c = llm_mod.VultrInference()
    c._model = "m"
    budgets = []

    def fake_post(url, headers, json, timeout):
        budgets.append(json["max_tokens"])
        if len(budgets) == 1:
            return Resp(200, {"choices": [{"finish_reason": "length", "message": {"content": "thinking…"}}]})
        return Resp(200, {"choices": [{"finish_reason": "tool_calls", "message": {"tool_calls": [
            {"id": "1", "function": {"name": "submit_plan", "arguments": "{\"harness_code\": \"x\"}"}}]}}]})

    monkeypatch.setattr(llm_mod.httpx, "post", fake_post)
    msg = c.chat([{"role": "user", "content": "hi"}], max_tokens=1000)
    assert budgets == [1000, 2000] and msg["tool_calls"]


def test_forced_tool_choice_falls_back_to_auto(monkeypatch):
    c = llm_mod.VultrInference()
    c._model = "m"
    seen = []

    def fake_post(url, headers, json, timeout):
        seen.append(json.get("tool_choice"))
        if json.get("tool_choice") == "required":
            return Resp(400, {"error": "tool_choice required not supported"})
        return Resp(200, {"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]})

    monkeypatch.setattr(llm_mod.httpx, "post", fake_post)
    c.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function", "function": {"name": "f"}}],
           tool_choice="required")
    assert seen == ["required", "auto"]


def test_tool_args_tolerates_fenced_json():
    call = {"function": {"arguments": "```json\n{\"a\": 1}\n```"}}
    assert llm_mod.tool_args(call) == {"a": 1}
