-- Allow the 'archived' scan status.
--
-- Archiving sets old/test scans aside: they stay visible in the scan list with an
-- 'archived' badge but drop out of the active "Vulnerabilities" overview (the
-- project-stats aggregate excludes them). The original CHECK from 0001 only
-- permitted pending/running/completed/failed/cancelled, so a status='archived'
-- write would otherwise violate it. Idempotent: drop the inline 0001 check by its
-- default name, then re-add the widened one.
ALTER TABLE scan DROP CONSTRAINT IF EXISTS scan_status_check;
ALTER TABLE scan ADD CONSTRAINT scan_status_check
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'archived'));
