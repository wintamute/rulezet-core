# syntax=docker/dockerfile:1

# --- builder ---
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

WORKDIR /app

# Build deps for yara-python (bundles libyara) and other native packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libmagic-dev \
    automake \
    libtool \
    flex \
    bison \
    libjansson-dev \
    && rm -rf /var/lib/apt/lists/*

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Install dependencies first (better layer caching — source changes won't bust this)
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev


# --- runtime ---
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

# Runtime-only native deps:
#   libmagic1      – yara magic-match support
#   libjansson4    – libyara JSON support
#   git            – GitHub import pipeline clones repos at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    libjansson4 \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /app/.venv

COPY . .

RUN chmod +x entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FLASKENV=production
ENV DB_HOST=db
ENV DB_PORT=5432

EXPOSE 7009

ENTRYPOINT ["./entrypoint.sh"]
