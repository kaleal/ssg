ARG BASE=ubuntu:noble
FROM ${BASE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ansible-core python3-pytest python3-jinja2 python3-yaml libpam-pwquality pamtester openscap-scanner linux-base && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
ENV PYTHONPATH=/workspace SSG_PAM_TEST_DISPOSABLE=1
