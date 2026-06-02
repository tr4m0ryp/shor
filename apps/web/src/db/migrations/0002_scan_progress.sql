-- 0002_scan_progress.sql — live run-progress snapshot (ADR-051 feed).
--
-- The Cloud Run Job worker pushes a progress snapshot (current phase/agent +
-- completed-agent records) to the findings sink as it walks the pipeline. We
-- store the latest snapshot verbatim as JSONB on the scan row; the activity tab
-- polls a read route that blends it with the static phase/agent taxonomy. NULL
-- until the worker posts its first update.
ALTER TABLE scan ADD COLUMN IF NOT EXISTS progress JSONB;
