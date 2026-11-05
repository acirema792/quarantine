"""A scripted stand-in for Vultr Serverless Inference (OpenAI-compatible) used by
the test-suite. It exercises the real code paths: model listing, tool calling,
multi-turn tool results, forced tool_choice, and the harness self-healing loop.

Run standalone:  python -m uvicorn tests.mock_inference:app --port 8099
"""
import json
import re

from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI()
CALLS = []  # recorded request bodies (for assertions)


@app.get("/v1/models")
def models(authorization: str = Header("")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing key")
    return {"object": "list", "data": [
        {"id": "qwen3.8-flash-next", "object": "model", "features": ["tools"]},
        {"id": "kimi-k2-instruct", "object": "model", "features": ["tools"]},
    ]}


def _tool_call(name, args, i=0):
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": f"call_{name}_{i}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


def _resp(model, msg):
    return {"id": "mock", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}],
            "usage": {"prompt_tokens": 512, "completion_tokens": 128, "total_tokens": 640}}


@app.post("/v1/chat/completions")
async def chat(req: Request, authorization: str = Header("")):
    if authorization != "Bearer test-vultr-key":
        raise HTTPException(401, "bad key")
    body = await req.json()
    CALLS.append(body)
    model = body["model"]
    tools = {t["function"]["name"] for t in body.get("tools") or []}
    msgs = body["messages"]
    user0 = next((m["content"] for m in msgs if m["role"] == "user"), "")

    if "write_report" in tools:
        ev = json.loads(user0.split("<evidence>\n", 1)[1].split("\n</evidence>")[0])
        return _resp(model, _tool_call("write_report", {
            "headline": f"{ev['package']} — {ev['verdict'].lower()}",
            "summary": f"Mock summary over {len(ev['signals'])} signals.",
            "recommendation": "Block it." if ev["verdict"] == "MALICIOUS" else "Approve it."}))

    m = re.search(r"Package: (\w+):([^@\s]+)@", user0) or re.search(r"for (\w+):([^@\s]+)@", user0)
    eco, name = (m.group(1), m.group(2)) if m else ("npm", "unknown")

    if "crashed inside the sandbox" in user0:  # heal request
        return _resp(model, _tool_call("submit_plan", {
            "claimed_purpose": "fixed", "harness_language": "node" if eco == "npm" else "python",
            "harness_code": _harness(eco, name, buggy=False)}))

    tool_turns = sum(1 for x in msgs if x["role"] == "tool")
    if tool_turns == 0:
        return _resp(model, _tool_call("list_files", {}))
    if tool_turns == 1:
        target = "package.json" if eco == "npm" else "setup.py"
        return _resp(model, _tool_call("read_file", {"path": target}, 1))
    # The test asks for a buggy first harness for left-padder to exercise self-healing
    return _resp(model, _tool_call("submit_plan", {
        "claimed_purpose": f"{name} (mock analyst)",
        "execution_points": ["install hook" if eco == "npm" else "setup.py"],
        "suspicions": ["check install-time network calls"],
        "harness_language": "node" if eco == "npm" else "python",
        "harness_code": _harness(eco, name, buggy=(name == "left-padder"))}, 2))


def _harness(eco, name, buggy):
    if eco == "npm":
        call = "consol.log" if buggy else "console.log"
        return (f"const m = require({json.dumps(name)});\n"
                f"const out = Object.keys(m).map(k => [k, typeof m[k]]);\n"
                f"if (m.leftPad) out.push(['leftPad', m.leftPad('7', 3, '0')]);\n"
                f"{call}(JSON.stringify(out));\n")
    mod = name.replace("-", "_")
    return f"import json, {mod}\nprint(json.dumps(sorted(a for a in dir({mod}) if not a.startswith('_'))))\n"
