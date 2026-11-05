"""Vultr Serverless Inference client (OpenAI-compatible chat completions + tools).

The API key lives only here, on the control plane. It is never written into a
job file, an environment passed to a sandbox, a log line or a receipt.
"""
from __future__ import annotations

import json
import time

import httpx

from .config import settings


class LLMError(RuntimeError):
    pass


class VultrInference:
    def __init__(self):
        self.base = settings.inference_base.rstrip("/")
        self.key = settings.inference_key
        self._models = None
        self._model = None
        self.last_error = None

    @property
    def enabled(self):
        return bool(self.key)

    def _headers(self):
        return {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}

    def models(self):
        if self._models is None:
            r = httpx.get(f"{self.base}/models", headers=self._headers(), timeout=20)
            r.raise_for_status()
            self._models = r.json().get("data", [])
        return self._models

    def model(self):
        """First preferred model that the live catalog actually offers."""
        if self._model:
            return self._model
        try:
            ids = [m.get("id") for m in self.models()]
        except Exception as exc:
            self.last_error = f"model list failed: {exc}"
            ids = []
        for pref in settings.model_prefs:
            if pref in ids:
                self._model = pref
                return pref
        # fall back: any model that advertises tool support, else the first one
        for m in self._models or []:
            if "tools" in json.dumps(m).lower():
                self._model = m["id"]
                return self._model
        self._model = ids[0] if ids else settings.model_prefs[0]
        return self._model

    def chat(self, messages, tools=None, tool_choice=None, max_tokens=1800, temperature=0.2, on_usage=None):
        if not self.enabled:
            raise LLMError("VULTR_INFERENCE_API_KEY not configured")
        body = {"model": self.model(), "messages": messages, "max_tokens": max_tokens,
                "temperature": temperature}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice or "auto"
        last = None
        for attempt in range(3):
            t0 = time.time()
            try:
                r = httpx.post(f"{self.base}/chat/completions", headers=self._headers(), json=body,
                               timeout=settings.llm_timeout)
                if r.status_code == 429 or r.status_code >= 500:
                    last = f"HTTP {r.status_code}: {r.text[:200]}"
                    time.sleep(1.5 * (attempt + 1))
                    continue
                if r.status_code >= 400 and tools and tool_choice not in (None, "auto") and attempt == 0:
                    body["tool_choice"] = "auto"  # some models reject forced tool_choice
                    last = f"HTTP {r.status_code}: {r.text[:200]}"
                    continue
                r.raise_for_status()
                data = r.json()
                usage = data.get("usage") or {}
                if on_usage:
                    on_usage({"model": body["model"], "latency_s": round(time.time() - t0, 2),
                              "prompt_tokens": usage.get("prompt_tokens"),
                              "completion_tokens": usage.get("completion_tokens")})
                return data["choices"][0]["message"]
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                last = str(exc)
                time.sleep(1.0 * (attempt + 1))
        self.last_error = last
        raise LLMError(last or "inference failed")


def tool_args(call):
    raw = (call.get("function") or {}).get("arguments") or "{}"
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        # tolerate models that wrap JSON in prose / code fences
        s, e = raw.find("{"), raw.rfind("}")
        if s >= 0 and e > s:
            try:
                return json.loads(raw[s:e + 1])
            except ValueError:
                pass
    return {}


llm = VultrInference()
