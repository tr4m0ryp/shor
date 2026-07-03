# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2025-2026 Keygraph, Inc.
# Required Notice: Shor -- https://github.com/tr4m0ryp/shor
# Noncommercial use only. Selling this software or offering it as a paid or
# hosted service requires a separate commercial license. See LICENSE & NOTICE.

# Serves codesage-large-v2 (code) + gte-large-en-v1.5 (text) + bge-reranker-v2-m3
# over HTTP. All three need trust_remote_code / a custom HF architecture, so TEI
# cannot host them -- this is the documented FastAPI fallback (see README).
#
# Base ships torch 2.5.1 + CUDA 12.1 so GPU wheels are already resolved.
FROM pytorch/pytorch:2.5.1-cuda12.1-cudnn9-runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/models \
    HF_HUB_ENABLE_HF_TRANSFER=0 \
    EMBED_DEVICE=cuda

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY server ./server

# Model weights are NOT baked in -- mount /models (HF_HOME) as a cache volume so
# the ~4.5 GB of weights download once and persist across restarts.
VOLUME ["/models"]
EXPOSE 8080

# Run unprivileged. Single uvicorn worker: the models are large and thread-safe
# batching within one process beats N copies of the weights.
RUN useradd --create-home --uid 65532 shor && mkdir -p /models && chown shor /models
USER shor

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
