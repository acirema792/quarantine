# Detonation sandbox image. Holds NO secrets; the only Quarantine code inside is
# the stdlib-only runner. Everything sensitive lives on the control plane.
ARG BASE=node:22-bookworm-slim
FROM ${BASE}
ARG INSTALL_PKGS=1
RUN if [ "$INSTALL_PKGS" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-setuptools procps ca-certificates && \
      rm -rf /var/lib/apt/lists/*; \
    fi
RUN useradd -u 10001 -m -d /home/dev -s /bin/sh dev
COPY runner.py /opt/quarantine/runner.py
USER 10001:10001
WORKDIR /work
ENV HOME=/home/dev
ENTRYPOINT ["python3", "-u", "/opt/quarantine/runner.py"]
