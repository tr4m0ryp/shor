# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2025-2026 Keygraph, Inc.
# Required Notice: Shor -- https://github.com/tr4m0ryp/shor
# Noncommercial use only. Selling this software or offering it as a paid or
# hosted service requires a separate commercial license. See LICENSE & NOTICE.

"""Runtime configuration for the Shor embed/rerank model server.

All three models are Apache-2.0 / MIT (commercially clean, self-hostable).
Overridable via env so an operator can swap the text embedder to bge-m3 (MIT)
or point at a local snapshot without a code change.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _detect_device() -> str:
    forced = os.getenv("EMBED_DEVICE")
    if forced:
        return forced
    try:  # torch is optional at import time (config is import-safe on CPU-less hosts)
        import torch

        if torch.cuda.is_available():
            return "cuda"
    except Exception:
        pass
    return "cpu"


@dataclass(frozen=True)
class Settings:
    # code = codesage-large-v2 (Apache-2.0), 2048-dim native, truncated to 1024.
    code_model: str = field(
        default_factory=lambda: os.getenv(
            "EMBED_CODE_MODEL", "codesage/codesage-large-v2"
        )
    )
    # text = gte-large-en-v1.5 (Apache-2.0) by default; swap to BAAI/bge-m3 (MIT).
    text_model: str = field(
        default_factory=lambda: os.getenv(
            "EMBED_TEXT_MODEL", "Alibaba-NLP/gte-large-en-v1.5"
        )
    )
    # reranker = bge-reranker-v2-m3 (Apache-2.0). NEVER jina-reranker (CC-BY-NC).
    rerank_model: str = field(
        default_factory=lambda: os.getenv(
            "EMBED_RERANK_MODEL", "BAAI/bge-reranker-v2-m3"
        )
    )
    device: str = field(default_factory=_detect_device)
    use_fp16: bool = field(
        default_factory=lambda: os.getenv("EMBED_FP16", "1") != "0"
    )
    # Optional bearer; when set, every request must send Authorization: Bearer <token>.
    token: str | None = field(default_factory=lambda: os.getenv("SHOR_EMBED_TOKEN") or None)
    # Server-side hard cap mirroring the client (spec T4: rerank <= ~50 candidates).
    max_rerank: int = field(
        default_factory=lambda: int(os.getenv("EMBED_MAX_RERANK", "50"))
    )
    default_code_dim: int = 1024


settings = Settings()
