.PHONY: images dev test selftest
images:
	docker build -t quarantine-sandbox:latest sandbox/
	docker build -t quarantine-proxy:latest proxy/
dev:
	python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt
	.venv/bin/uvicorn app.main:app --reload --port 8000
test:
	.venv/bin/python -m pytest -q tests/
selftest:
	deploy/selftest.sh http://127.0.0.1:8000
