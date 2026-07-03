# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2025-2026 Keygraph, Inc.
# Required Notice: Shor -- https://github.com/tr4m0ryp/shor
# Noncommercial use only. Selling this software or offering it as a paid or
# hosted service requires a separate commercial license. See LICENSE & NOTICE.

"""Wire schemas for the embed/rerank HTTP API.

These mirror the TypeScript client contract in
apps/worker/src/services/memory/embed/. Field names are snake_case on the wire
(token_counts, truncate_dim, top_k) and the client maps them to camelCase.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class EmbedRequest(BaseModel):
    inputs: list[str] = Field(..., description="Texts to embed, in order.")
    normalize: bool = Field(True, description="L2-normalize each vector server-side.")


class EmbedCodeRequest(EmbedRequest):
    truncate_dim: int = Field(
        1024, ge=1, description="Matryoshka truncation dim (codesage 2048 -> 1024)."
    )


class EmbedResponse(BaseModel):
    model: str
    dim: int
    embeddings: list[list[float]]
    # Per-input model token length -- the caller's late-chunking length hint.
    token_counts: list[int]


class RerankRequest(BaseModel):
    query: str
    passages: list[str]
    top_k: int | None = Field(None, ge=1, description="Return only the top-k hits.")


class RerankHit(BaseModel):
    index: int
    score: float


class RerankResponse(BaseModel):
    model: str
    results: list[RerankHit]


class HealthResponse(BaseModel):
    status: str
    device: str
    models: dict[str, str]
