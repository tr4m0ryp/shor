-- Human-approval launch tokens for the MCP connector (Claude routines).
--
-- A scan started through the Shor MCP connector may ONLY begin with a valid,
-- single-use, scope-bound, unexpired `launch_token`. The operator's approval
-- backend (the Telegram Approve button) mints a token bound to an engagement and
-- to a hash of the signed Rules-of-Engagement (RoE); the MCP's `start_blackbox_run`
-- can only CONSUME a token, never mint one. That separation is what keeps a human
-- structurally in the loop — an autonomous routine possesses no token and no way
-- to make one.
--
-- `roe` is added to `project` so the SIGNED allowlist attached at launch is the
-- exact allowlist Shor's own default-deny enforces on every network action; if the
-- persisted RoE is absent/invalid the orchestrator falls back to the target-URL
-- derived single-host RoE (default-deny either way). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS launch_token (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token         TEXT NOT NULL UNIQUE,          -- opaque, high-entropy, single-use
    engagement_id TEXT NOT NULL,                 -- the signed engagement this authorizes
    roe_hash      TEXT NOT NULL,                 -- sha256 of the canonical signed RoE
    expires_at    TIMESTAMPTZ NOT NULL,          -- hard TTL; consume rejects when past
    used_at       TIMESTAMPTZ,                   -- NULL until consumed; set once, atomically
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The signed RoE attached to a project at launch (the enforced allowlist).
ALTER TABLE project ADD COLUMN IF NOT EXISTS roe JSONB;

COMMIT;
