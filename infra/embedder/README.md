# Shor embed + rerank model server

A small self-hosted HTTP server (beside DeepSeek) that serves the three
commercially-clean models the RAG learning-memory layer needs (spec T5 / F13).
All downstream RAG tasks embed/rerank through this one seam; the worker client
lives at `apps/worker/src/services/memory/embed/`.

| Role | Model | Dim | Max ctx | License |
|---|---|---|---|---|
| Code embedding | `codesage/codesage-large-v2` | 2048 -> **1024** (Matryoshka truncate) | 2048 tok | Apache-2.0 |
| Text embedding | `Alibaba-NLP/gte-large-en-v1.5` (or `BAAI/bge-m3`) | 1024 | 8192 tok | Apache-2.0 / MIT |
| Reranker | `BAAI/bge-reranker-v2-m3` | -- | 512-8192 tok | Apache-2.0 |

**Never** use CC-BY-NC models (SFR-Code, jina-code, jina-reranker) — non-commercial
licenses are barred for a paid product (rules.md "DO NOT").

## Why FastAPI and not TEI

The task's first choice was HuggingFace Text Embeddings Inference (TEI). TEI
serves `bge-m3` and `bge-reranker-v2-m3` natively, but **cannot** serve
`codesage-large-v2`: codesage ships a custom `CodeSage` architecture that needs
`trust_remote_code=True`, which TEI does not load (`gte-large-en-v1.5` is in the
same boat). Rather than run TEI for two models and a second server for codesage,
this is one uniform FastAPI server for all three (via `sentence-transformers` +
`FlagEmbedding`). No model is silently dropped (stop-condition satisfied).

## Wire API

`token_counts[i]` is the model token length of `inputs[i]` — the "length hint"
task 011 uses to decide whether to late-chunk a snippet before embedding.
codesage max context is **2048 tokens**; chunk longer code upstream.

```
GET  /healthz
  -> { "status": "ok", "device": "cuda",
       "models": { "code": "...", "text": "...", "reranker": "..." } }

POST /embed/code
  { "inputs": ["def f(): ..."], "normalize": true, "truncate_dim": 1024 }
  -> { "model": "codesage/codesage-large-v2", "dim": 1024,
       "embeddings": [[...1024 floats...]], "token_counts": [37] }

POST /embed/text
  { "inputs": ["verbalized finding ..."], "normalize": true }
  -> { "model": "Alibaba-NLP/gte-large-en-v1.5", "dim": 1024,
       "embeddings": [[...1024 floats...]], "token_counts": [52] }

POST /rerank
  { "query": "...", "passages": ["...", "..."], "top_k": 8 }
  -> { "model": "BAAI/bge-reranker-v2-m3",
       "results": [ { "index": 1, "score": 0.98 }, { "index": 0, "score": 0.11 } ] }
```

- Code vectors are truncated to `truncate_dim` **then** L2-normalized (correct
  Matryoshka order). The pgvector store (task 001) expects unit vectors, so keep
  `normalize: true`.
- `/rerank` scores are sigmoid-normalized (0..1), sorted descending, and the
  server hard-caps input passages at `EMBED_MAX_RERANK` (default 50, spec T4).

## Auth

Set `SHOR_EMBED_TOKEN` on the server to require `Authorization: Bearer <token>`
on every request. Unset = open (dev / trusted network only). The worker client
reads the same var name (`SHOR_EMBED_TOKEN`) and attaches the bearer.

## Run it

### Docker (GPU)

```sh
cd infra/embedder
docker compose up --build          # exposes http://localhost:8080
# or plain docker:
docker build -t shor-embedder .
docker run --gpus all -p 8080:8080 -v hf-cache:/models shor-embedder
```

Weights are **not** baked into the image. On first request each model downloads
into `/models` (`HF_HOME`); mount it as a volume so the ~4.5 GB persists.
`/healthz` responds immediately (no model load); the first `/embed/*` or
`/rerank` call pays the one-time download + load latency.

### Bare metal (dev)

```sh
cd infra/embedder
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
EMBED_DEVICE=cpu uvicorn server.app:app --host 0.0.0.0 --port 8080
```

CPU works for development but is slow; use a GPU for real batches.

### Wire the worker

```sh
export SHOR_EMBED_URL=http://localhost:8080      # unset => client is a no-op
export SHOR_EMBED_TOKEN=change-me                # optional, must match server
```

## Config (env)

| Var | Default | Purpose |
|---|---|---|
| `EMBED_CODE_MODEL` | `codesage/codesage-large-v2` | code embedder id |
| `EMBED_TEXT_MODEL` | `Alibaba-NLP/gte-large-en-v1.5` | text embedder id (swap `BAAI/bge-m3`) |
| `EMBED_RERANK_MODEL` | `BAAI/bge-reranker-v2-m3` | reranker id |
| `EMBED_DEVICE` | auto (`cuda` if available else `cpu`) | torch device |
| `EMBED_FP16` | `1` | fp16 reranker weights |
| `EMBED_MAX_RERANK` | `50` | server-side rerank input cap |
| `SHOR_EMBED_TOKEN` | unset | required bearer when set |
| `HF_HOME` | `/models` | weight cache dir |

## Host / GPU sizing

Approx fp16 weight footprint: codesage-large-v2 ~2.6 GB, gte-large-en-v1.5
~0.9 GB, bge-reranker-v2-m3 ~1.1 GB — ~4.6 GB resident plus batch activations.

- **Recommended:** one GPU with >= 16 GB VRAM (NVIDIA T4 16 GB or L4 24 GB is
  plenty) running all three models in one process.
- **Minimum:** ~8 GB VRAM if you keep batches small.
- **CPU-only:** functional for dev, too slow for production batches.

Batch embeddings (the client chunks at 64/req by default) and cap rerank input
to ~50 candidates to bound memory. Exact throughput/sizing on the target GPU is
still to be measured — this documents the requirement; tune in CI/staging.
