-- 0006_scan_report: store the finalized executive report on the scan row.
--
-- The cli-finalization stage-3 report used to be written to the Sinas `<ns>/reports`
-- store and proxied by GET /scans/:id/report. Sinas was decommissioned; the worker now
-- POSTs the structured report through the findings sink and the dashboard serves it from
-- here. Nullable: existing scans (and runs whose finalize produced no report) have none.
ALTER TABLE scan ADD COLUMN IF NOT EXISTS report jsonb;
