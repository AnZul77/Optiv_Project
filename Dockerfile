# ==============================================================================
# PII Security Firewall - Production Gateway Container
# Multimodal AI Security Gateway (OCR, Detection, Sanitization & Verification)
# ==============================================================================

FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true

WORKDIR /app

# Install system dependencies (OpenCV headless runtime, GLib, curl for healthcheck, poppler, tesseract)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libgl1 \
    libglib2.0-0 \
    tesseract-ocr \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_sm

# Pre-cache EasyOCR CRAFT detection & CRNN recognition models to prevent runtime download delays
RUN python -c "import easyocr; easyocr.Reader(['en'], gpu=False)"

# Copy application source code and configurations
COPY config/ ./config/
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY docs/ ./docs/
COPY data/ground_truth/ ./data/ground_truth/
COPY data/raw/ ./data/raw/
COPY data/outputs/ocr_cache_policy_v6.json ./data/outputs/ocr_cache_policy_v6.json
COPY app.py .
COPY README.md .

# Ensure outputs and logs directory structure exists
RUN mkdir -p data/outputs reports/logs

# Expose Streamlit default web port
EXPOSE 8501

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Launch Streamlit Gateway UI
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
