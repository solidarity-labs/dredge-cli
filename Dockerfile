FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy metadata first (for caching)
COPY pyproject.toml README.md ./

# Create venv and upgrade pip
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip

# Copy the actual package
COPY dredge/ ./dredge/

# Install this project (and all dependencies from pyproject.toml)
RUN /opt/venv/bin/pip install .

# -------------------------
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN useradd --create-home --shell /usr/sbin/nologin dredge && \
    chown -R dredge:dredge /app
USER dredge

ENTRYPOINT ["dredge"]
CMD ["--help"]
