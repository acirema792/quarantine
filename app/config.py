"""Runtime configuration (environment variables only; see .env.example)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Settings:
    # --- Vultr Serverless Inference (OpenAI-compatible) -------------------
    inference_base = os.environ.get("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1")
    inference_key = os.environ.get("VULTR_INFERENCE_API_KEY", "")
    # Comma-separated preference list; first one present in /v1/models wins.
    model_prefs = [m.strip() for m in os.environ.get(
        "VULTR_MODEL",
        "kimi-k2-instruct,kimi-k2.6,glm-5.3,glm-5.2,deepseek-v4.1-flash,qwen3.8-flash-next,gpt-oss-120b",
    ).split(",") if m.strip()]
    llm_timeout = _int("LLM_TIMEOUT", 90)

    # --- Sandbox ---------------------------------------------------------
    sandbox_image = os.environ.get("SANDBOX_IMAGE", "quarantine-sandbox:latest")
    proxy_image = os.environ.get("PROXY_IMAGE", "quarantine-proxy:latest")
    # "auto" -> runsc (gVisor) when Docker has it, else runc with a loud warning
    runtime = os.environ.get("SANDBOX_RUNTIME", "auto")
    mem_limit = os.environ.get("SANDBOX_MEMORY", "768m")
    nano_cpus = int(float(os.environ.get("SANDBOX_CPUS", "1")) * 1e9)
    pids_limit = _int("SANDBOX_PIDS", 256)
    run_timeout = _int("SANDBOX_TIMEOUT", 150)  # hard wall clock for the whole detonation
    registry_hosts = os.environ.get(
        "REGISTRY_ALLOW", "registry.npmjs.org,pypi.org,files.pythonhosted.org").split(",")
    upstream_proxy = os.environ.get("UPSTREAM_PROXY", "")  # dev environments only
    max_concurrent = _int("MAX_CONCURRENT_RUNS", 2)
    # Every detonation network is carved out of this /16 so one host firewall rule
    # (INPUT -s <pool> -j DROP) stops sandboxes from reaching the VM itself (sshd, Caddy...).
    subnet_pool = os.environ.get("SANDBOX_SUBNET_POOL", "10.250")
    manage_firewall = os.environ.get("MANAGE_HOST_FIREWALL", "1") == "1"

    # --- App -------------------------------------------------------------
    data_dir = Path(os.environ.get("DATA_DIR", ROOT / "data"))
    fixtures_dir = ROOT / "fixtures"
    max_package_mb = _int("MAX_PACKAGE_MB", 25)
    # Public demo mode: only bundled fixtures + real registry packages, no uploads.
    allow_registry_targets = os.environ.get("ALLOW_REGISTRY_TARGETS", "1") == "1"
    admin_token = os.environ.get("ADMIN_TOKEN", "")  # protects approve/block when set
    rate_limit_per_hour = _int("RATE_LIMIT_PER_HOUR", 30)
    public_url = os.environ.get("PUBLIC_URL", "")


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
