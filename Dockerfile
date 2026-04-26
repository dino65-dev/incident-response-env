# =============================================================================
# Dockerfile for HF Spaces — GRPO SOC Training + Live Dashboard
#
# Runs on GPU Space (T4/A10G). Installs unsloth, trl, project modules.
# Launches Gradio dashboard that can trigger training and show live graphs.
#
# HF Spaces config in README.md:
#   sdk: docker
#   app_port: 7860
# =============================================================================

FROM pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime

# System deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc g++ git curl \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (HF Spaces requirement)
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1

WORKDIR /home/user/app

# Install training stack
RUN pip install --no-cache-dir --user \
    unsloth vllm \
    "trl==0.22.2" \
    "transformers==4.56.2" \
    "datasets>=2.18.0" \
    "accelerate>=0.30.0" \
    "peft>=0.12.0" \
    "bitsandbytes>=0.44.0" \
    "gradio>=5.0.0" \
    "matplotlib>=3.8.0" \
    "numpy>=1.24.0" \
    "openenv-core"

# Copy entire project (modules, tasks, training, etc.)
COPY --chown=user:user . .

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/')" || exit 1

CMD ["python", "gradio_dashboard.py"]
