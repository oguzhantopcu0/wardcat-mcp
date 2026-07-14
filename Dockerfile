# syntax=docker/dockerfile:1
#
# wardcat-mcp — a stdio MCP server. Clients spawn it as a subprocess, so the
# container is run interactively and talks over stdin/stdout:
#
#   docker build -t wardcat-mcp .
#   docker run -i --rm -e WARDCAT_SALT=your-secret wardcat-mcp
#
# To include the SpaCy NER layer (PERSON/ORG/ADDRESS), build with:
#   docker build --build-arg EXTRAS='[ner]' -t wardcat-mcp:ner .

# ---- builder -------------------------------------------------------------
FROM python:3.12-slim AS builder

# uv for fast, reproducible installs.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app
RUN uv venv "$VIRTUAL_ENV"

# Metadata + sources needed to build and install the wheel.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Optional extras (e.g. '[ner]'). Empty by default to keep the image small.
ARG EXTRAS=""
RUN uv pip install ".${EXTRAS}"

# ---- runtime -------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/oguzhantopcu0/wardcat-mcp" \
      org.opencontainers.image.description="MCP server exposing wardcat's on-prem PII/sensitive-data detection & anonymization as agent tools" \
      org.opencontainers.image.licenses="MIT"

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 wardcat

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

COPY --from=builder /opt/venv /opt/venv

USER wardcat
WORKDIR /home/wardcat

# stdio transport: run with `docker run -i` so the client can drive stdin/stdout.
ENTRYPOINT ["wardcat-mcp"]
