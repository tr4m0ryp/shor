// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// Main shell of the pentest/report-view component — the no-login SHOWCASE
// surface. assemble.py concatenates report-view.parts.jsx ABOVE this file into
// the single module that becomes spec.components[0].code.
//
//   enabled_stores:    pentest/{findings,reports,scans,projects}
//   enabled_functions: pentest/{trigger_scan,create_project}
//
// SDK contract (from the Sinas component spec; the public OpenAPI is a stub, so
// the surface is confirmed at apply — see report-view.parts.jsx FLAGs):
//   - React is a runtime global; this is `export default function App(props)`.
//   - `props.input_data` is the immutable snapshot the runtime injects from the
//     enabled stores; the spec flags the live `/proxy/states` path as finicky,
//     so we render from the snapshot (readStore prefers it).
//   - Run/rerun + New-project write ONLY through the two enabled functions.
//
// No tokens/hosts are baked in: the engine bearer lives only on the `engine`
// connector (server side); this bundle never sees it.
//
// The `import` line below is a SOURCE-ONLY shim so this file passes
// `node --check --input-type=module` standalone; assemble.py strips it because
// the concatenated parts fragment already defines every referenced name in the
// same module scope.
import {
  React,
  useState,
  useMemo,
  useCallback,
  STORES,
  FUNCTIONS,
  readStore,
  valueOf,
  invokeFunction,
  ui,
  StatusPill,
  Findings,
  Report,
  NewProjectForm,
} from "./report-view.parts.jsx";

export default function App(props) {
  const inputData = (props && props.input_data) || {};
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const projects = useMemo(() => readStore(inputData, STORES.projects).map(valueOf), [inputData]);
  const scans = useMemo(() => readStore(inputData, STORES.scans).map(valueOf), [inputData]);
  const findings = useMemo(() => readStore(inputData, STORES.findings).map(valueOf), [inputData]);
  const reports = useMemo(() => readStore(inputData, STORES.reports), [inputData]);
  // Repos are NOT one of the four stores: the engine exposes them live via the
  // connector's list_repos op. The runtime may surface that op result in the
  // snapshot under "pentest/repos"; absent it, the form shows black-box only.
  const repos = useMemo(() => readStore(inputData, "pentest/repos").map(valueOf), [inputData]);
  const reposConnected = repos.length > 0;

  const reportFor = useCallback(
    (scanId) => {
      const hit = reports.find((s) => s.key === scanId);
      return hit ? valueOf(hit) : undefined;
    },
    [reports],
  );
  const scansFor = useCallback(
    (projectId) =>
      scans
        .filter((s) => s.projectId === projectId)
        .sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || ""))),
    [scans],
  );
  const findingsFor = useCallback(
    (scanId) => findings.filter((f) => f.scanId === scanId || f.scan_id === scanId),
    [findings],
  );

  const guard = useCallback(async (fn) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      if (typeof ui().refresh === "function") ui().refresh();
    } catch (e) {
      setError(e && e.message ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  const runScan = (projectId, ref) =>
    guard(() => invokeFunction(FUNCTIONS.triggerScan, ref ? { projectId, ref } : { projectId }));
  const createProject = (payload) => guard(() => invokeFunction(FUNCTIONS.createProject, payload));

  return React.createElement(
    "div",
    { style: { fontFamily: "system-ui, sans-serif", maxWidth: 820, margin: "0 auto", padding: 16 } },
    React.createElement("h2", null, "Aegis — pentest showcase"),
    error ? React.createElement("p", { style: { color: "#b00020" } }, `Error: ${error}`) : null,
    projects.length === 0 ? React.createElement("p", { style: { color: "#777" } }, "No projects yet.") : null,
    projects.map((p) => {
      const runs = scansFor(p.projectId);
      return React.createElement(
        "section",
        { key: p.projectId, style: { border: "1px solid #e3e3e3", borderRadius: 8, padding: 12, margin: "10px 0" } },
        React.createElement(
          "div",
          { style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
          React.createElement("h3", { style: { margin: 0 } }, p.name || p.projectId),
          React.createElement("button", { disabled: busy, onClick: () => runScan(p.projectId) }, "Run / rerun"),
        ),
        React.createElement(
          "div",
          { style: { color: "#666", fontSize: 13 } },
          `${p.targetUrl || ""} · ${p.mode || "blackbox"}`,
        ),
        React.createElement(
          "ul",
          { style: { listStyle: "none", padding: 0 } },
          runs.map((r) =>
            React.createElement(
              "li",
              { key: r.scanId, style: { padding: "4px 0", cursor: "pointer" }, onClick: () => setSelected(r.scanId) },
              React.createElement(StatusPill, { status: r.status, progress: r.progress }),
              React.createElement("span", { style: { marginLeft: 8 } }, r.scanId),
              selected === r.scanId
                ? React.createElement(
                    "div",
                    { style: { marginTop: 8, paddingLeft: 8, borderLeft: "2px solid #eee" } },
                    React.createElement("h4", null, "Findings"),
                    React.createElement(Findings, { findings: findingsFor(r.scanId) }),
                    React.createElement(Report, { report: reportFor(r.scanId) }),
                  )
                : null,
            ),
          ),
        ),
      );
    }),
    React.createElement(NewProjectForm, { repos, reposConnected, onCreate: createProject, busy }),
  );
}
