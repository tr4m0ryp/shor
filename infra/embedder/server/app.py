# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2025-2026 Keygraph, Inc.
# Required Notice: Shor -- https://github.com/tr4m0ryp/shor
# Noncommercial use only. Selling this software or offering it as a paid or
# hosted service requires a separate commercial license. See LICENSE & NOTICE.

"""FastAPI app exposing code/text embeddings + a reranker over HTTP.

Routes (see README for the wire contract, mirrored by the worker TS client):
    GET  /healthz       -> liveness + configured model ids (no model load)
    POST /embed/code    -> codesage-large-v2, truncated to 1024-dim
    POST /embed/text    -> gte-large-en-v1.5 / bge-m3, 1024-dim
    POST /rerank        -> bge-reranker-v2-m3 cross-encoder

When SHOR_EMBED_TOKEN is set the server requires a matching bearer on every
request; unset means open (dev / trusted-network only).
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException

from . import models
from .config import settings
from .schemas import (
    EmbedCodeRequest,
    EmbedRequest,
    EmbedResponse,
    HealthResponse,
    RerankHit,
    RerankRequest,
    RerankResponse,
)

app = FastAPI(title="Shor embedder + reranker", version="1")


def require_auth(authorization: str | None = Header(default=None)) -> None:
    if settings.token is None:
        return
    if authorization != f"Bearer {settings.token}":
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    return HealthResponse(
        status="ok",
        device=settings.device,
        models={
            "code": settings.code_model,
            "text": settings.text_model,
            "reranker": settings.rerank_model,
        },
    )


@app.post("/embed/code", response_model=EmbedResponse)
def embed_code(req: EmbedCodeRequest, _: None = Depends(require_auth)) -> EmbedResponse:
    model, dim, embeddings, counts = models.embed_code(
        req.inputs, req.normalize, req.truncate_dim
    )
    return EmbedResponse(model=model, dim=dim, embeddings=embeddings, token_counts=counts)


@app.post("/embed/text", response_model=EmbedResponse)
def embed_text(req: EmbedRequest, _: None = Depends(require_auth)) -> EmbedResponse:
    model, dim, embeddings, counts = models.embed_text(req.inputs, req.normalize)
    return EmbedResponse(model=model, dim=dim, embeddings=embeddings, token_counts=counts)


@app.post("/rerank", response_model=RerankResponse)
def rerank(req: RerankRequest, _: None = Depends(require_auth)) -> RerankResponse:
    capped = req.passages[: settings.max_rerank]
    model, hits = models.rerank(req.query, capped, req.top_k)
    return RerankResponse(
        model=model, results=[RerankHit(index=h["index"], score=h["score"]) for h in hits]
    )
