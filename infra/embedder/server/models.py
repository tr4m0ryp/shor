# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2025-2026 Keygraph, Inc.
# Required Notice: Shor -- https://github.com/tr4m0ryp/shor
# Noncommercial use only. Selling this software or offering it as a paid or
# hosted service requires a separate commercial license. See LICENSE & NOTICE.

"""Lazy-loaded model backends (code embedder, text embedder, reranker).

Loaded on first use so the container boots fast and `/healthz` never forces a
multi-GB download. codesage + gte need trust_remote_code=True (custom HF
architectures) -- which is exactly why TEI cannot serve them and we run a
FastAPI server instead (see README).
"""

from __future__ import annotations

import threading

import numpy as np

from .config import settings

_lock = threading.Lock()
_st_cache: dict[str, object] = {}
_reranker: object | None = None


def _get_embedder(model_id: str):
    from sentence_transformers import SentenceTransformer

    with _lock:
        model = _st_cache.get(model_id)
        if model is None:
            model = SentenceTransformer(
                model_id, trust_remote_code=True, device=settings.device
            )
            _st_cache[model_id] = model
    return model


def _get_reranker():
    global _reranker
    with _lock:
        if _reranker is None:
            from FlagEmbedding import FlagReranker

            _reranker = FlagReranker(
                settings.rerank_model, use_fp16=settings.use_fp16
            )
    return _reranker


def _l2_normalize(vecs: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return vecs / norms


def _token_counts(model, inputs: list[str]) -> list[int]:
    """True (un-truncated) token length per input -- the chunking length hint."""
    enc = model.tokenizer(inputs, add_special_tokens=True, truncation=False)
    return [len(ids) for ids in enc["input_ids"]]


def embed_code(
    inputs: list[str], normalize: bool, truncate_dim: int
) -> tuple[str, int, list[list[float]], list[int]]:
    """codesage-large-v2: encode full 2048-dim, Matryoshka-truncate, THEN normalize."""
    model = _get_embedder(settings.code_model)
    vecs = np.asarray(
        model.encode(inputs, convert_to_numpy=True, normalize_embeddings=False),
        dtype=np.float32,
    )
    if 0 < truncate_dim < vecs.shape[1]:
        vecs = vecs[:, :truncate_dim]
    if normalize:
        vecs = _l2_normalize(vecs)
    return settings.code_model, int(vecs.shape[1]), vecs.tolist(), _token_counts(model, inputs)


def embed_text(
    inputs: list[str], normalize: bool
) -> tuple[str, int, list[list[float]], list[int]]:
    """gte-large-en-v1.5 / bge-m3: 1024-dim native, normalized server-side."""
    model = _get_embedder(settings.text_model)
    vecs = np.asarray(
        model.encode(inputs, convert_to_numpy=True, normalize_embeddings=normalize),
        dtype=np.float32,
    )
    return settings.text_model, int(vecs.shape[1]), vecs.tolist(), _token_counts(model, inputs)


def rerank(
    query: str, passages: list[str], top_k: int | None
) -> tuple[str, list[dict[str, float]]]:
    """bge-reranker-v2-m3 cross-encoder; sigmoid-normalized scores, sorted desc."""
    reranker = _get_reranker()
    pairs = [[query, passage] for passage in passages]
    raw = reranker.compute_score(pairs, normalize=True)
    scores = [float(raw)] if isinstance(raw, (int, float)) else [float(s) for s in raw]
    hits = sorted(
        ({"index": i, "score": s} for i, s in enumerate(scores)),
        key=lambda hit: hit["score"],
        reverse=True,
    )
    if top_k is not None:
        hits = hits[:top_k]
    return settings.rerank_model, hits
