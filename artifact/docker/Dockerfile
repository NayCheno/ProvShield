FROM python:3.13-slim

LABEL maintainer="ProvShield Artifact"
LABEL description="Reproducible evaluation environment for ProvShield"

# Avoid interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /provshield

# Install system dependencies for report generation and shell scripts
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        make \
        jq \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifest first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy full project
COPY . .

# Default policy path inside the container
ENV PROVSHIELD_POLICY=artifact/configs/default_policy.yaml
ENV PROVSHIELD_SEED=42
ENV PYTHONPATH=/provshield/src

CMD ["bash"]
