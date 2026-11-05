# Per-run egress proxy: the only way out of a detonation network.
ARG BASE=python:3.12-slim
FROM ${BASE}
COPY egress_proxy.py /opt/quarantine/egress_proxy.py
USER 65534:65534
EXPOSE 3128
ENTRYPOINT ["python3", "-u", "/opt/quarantine/egress_proxy.py"]
