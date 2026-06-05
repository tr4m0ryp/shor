import pg from "../apps/web/node_modules/pg/lib/index.js";

const { Client } = pg;
const c = new Client({
  host: process.env.DBHOST,
  port: 5432,
  user: process.env.DBUSER,
  password: process.env.DBPASS,
  database: process.env.DBNAME,
  ssl: { rejectUnauthorized: false },
});
await c.connect();
const { rows } = await c.query(`
  SELECT s.id, s.status, s.started_at, p.name AS project,
         p.target_url,
         (SELECT count(*) FROM finding f WHERE f.scan_id = s.id) AS findings,
         (SELECT count(*) FROM attack_surface a WHERE a.scan_id = s.id) AS surfaces
  FROM scan s JOIN project p ON p.id = s.project_id
  ORDER BY s.started_at ASC NULLS LAST, s.id ASC
`);
rows.forEach((r, i) =>
  console.log(
    `#${i + 1} ${r.id} | ${r.status} | findings=${r.findings} surf=${r.surfaces} | ${r.project} | ${r.target_url ?? "?"} | ${r.started_at?.toISOString?.() ?? r.started_at}`,
  ),
);
await c.end();
