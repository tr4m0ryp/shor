// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// Presentational + SDK-shim fragment for the pentest/report-view component.
//
// This is NOT a standalone Sinas component. assemble.py concatenates this
// fragment ABOVE report-view.main.jsx into the single module that becomes
// spec.components[0].code (a Sinas component is one module). It is split out
// only to keep each source file under the 300-line cap; the names defined here
// (sdk, ui, readStore, valueOf, invokeFunction, SEVERITY_ORDER, LIVE_STATUSES,
// STORES, FUNCTIONS, and the small components) are referenced by the main shell.
//
// The `export` markers below let this file pass `node --check --input-type=module`
// on its own; assemble.py strips them when concatenating so the assembled module
// has plain top-level declarations sharing one scope with the main shell.

export const React = window.React;
export const { useState, useMemo, useCallback } = React;

export const STORES = {
  projects: "pentest/projects",
  scans: "pentest/scans",
  findings: "pentest/findings",
  reports: "pentest/reports",
};
export const FUNCTIONS = {
  triggerScan: "pentest/trigger_scan",
  createProject: "pentest/create_project",
};
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
export const LIVE_STATUSES = ["queued", "running", "pending"];

export const sdk = () => (typeof window !== "undefined" ? window.SinasSDK : undefined) || {};
export const ui = () => (typeof window !== "undefined" ? window.SinasUI : undefined) || {};

// --- store reads -----------------------------------------------------------
// Prefer the props snapshot (input_data); fall back to the live proxy only if
// the runtime did not inject one. Each state is { key, value, tags?, ... }.
export function readStore(inputData, storeRef) {
  const snap = inputData && (inputData[storeRef] || inputData[storeRef.split("/")[1]]);
  if (Array.isArray(snap)) return snap;
  if (snap && typeof snap === "object") {
    // Snapshot may arrive keyed by id; normalise to a {key,value} list.
    return Object.entries(snap).map(([key, value]) => ({ key, value }));
  }
  const live = sdk().stateList;
  if (typeof live === "function") {
    try {
      const res = live(storeRef);
      if (Array.isArray(res)) return res;
    } catch (_e) {
      /* proxy finicky — fall through to empty */
    }
  }
  return [];
}

// A state's payload, tolerating either {key,value} or a bare value object.
export const valueOf = (s) => (s && s.value !== undefined ? s.value : s) || {};

// --- function invocation ---------------------------------------------------
// The spec confirms functions run through window.SinasSDK but does not pin the
// method name. Try the documented candidates in order; the first callable wins.
// FLAG (apply-time): confirm the real method against the via-12 runtime and
// prune the rest — do NOT add new transport here.
export async function invokeFunction(ref, input) {
  const s = sdk();
  const [ns, name] = ref.split("/");
  const candidates = [
    () => s.runFunction && s.runFunction(ref, input),
    () => s.runFunction && s.runFunction(ns, name, input),
    () => s.callFunction && s.callFunction(ref, input),
    () => s.callFunction && s.callFunction(ns, name, input),
    () => s.invokeFunction && s.invokeFunction(ref, input),
    () => s.executeFunction && s.executeFunction(ref, input),
    () => s.functions && s.functions.run && s.functions.run(ref, input),
  ];
  for (const attempt of candidates) {
    const out = attempt();
    if (out !== undefined) return await out;
  }
  throw new Error(`No SinasSDK function-invoke method found for ${ref}`);
}

// --- small presentational helpers -----------------------------------------
export function StatusPill({ status, progress }) {
  const s = (status || "unknown").toLowerCase();
  const live = LIVE_STATUSES.includes(s);
  const tone = s === "failed" ? "#b00020" : s === "completed" ? "#1b7f3b" : live ? "#1456b8" : "#555";
  const label = live && Number.isFinite(progress) ? `${s} ${progress}%` : s;
  return React.createElement(
    "span",
    { style: { color: "#fff", background: tone, borderRadius: 10, padding: "1px 8px", fontSize: 12 } },
    label,
  );
}

export function SeverityBadge({ severity, confidence }) {
  const sev = (severity || "info").toLowerCase();
  const color =
    { critical: "#7a0012", high: "#b00020", medium: "#b8860b", low: "#2d6a4f", info: "#555" }[sev] || "#555";
  return React.createElement(
    "span",
    { style: { fontSize: 12 } },
    React.createElement("strong", { style: { color } }, sev.toUpperCase()),
    confidence ? ` · ${confidence}` : "",
  );
}

export function Findings({ findings }) {
  if (!findings.length) return React.createElement("p", { style: { color: "#777" } }, "No findings recorded.");
  return React.createElement(
    "ul",
    { style: { listStyle: "none", padding: 0 } },
    findings.map((f, i) =>
      React.createElement(
        "li",
        { key: f.fingerprint || f.id || i, style: { borderTop: "1px solid #eee", padding: "6px 0" } },
        React.createElement(SeverityBadge, { severity: f.severity, confidence: f.confidence }),
        React.createElement("div", null, f.title || f.category || f.id),
        f.evidence ? React.createElement("div", { style: { color: "#666", fontSize: 13 } }, f.evidence) : null,
      ),
    ),
  );
}

export function Report({ report }) {
  if (!report) return React.createElement("p", { style: { color: "#777" } }, "Report not finalized yet.");
  const counts = report.severity_counts || {};
  return React.createElement(
    "div",
    null,
    React.createElement("h3", null, report.report_title || "Security Assessment Report"),
    report.overall_risk ? React.createElement("p", null, `Overall risk: ${report.overall_risk}`) : null,
    React.createElement(
      "p",
      { style: { color: "#666", fontSize: 13 } },
      SEVERITY_ORDER.map((k) => `${k} ${counts[k] || 0}`).join(" · "),
    ),
    report.executive_summary ? React.createElement("p", null, report.executive_summary) : null,
    React.createElement(Findings, { findings: report.findings || [] }),
  );
}

export function NewProjectForm({ repos, reposConnected, onCreate, busy }) {
  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [mode, setMode] = useState("blackbox");
  const [repoRef, setRepoRef] = useState("");
  const submit = (e) => {
    e.preventDefault();
    const payload = { name, targetUrl, mode };
    if (mode === "whitebox" && repoRef) payload.repoRef = repoRef;
    onCreate(payload);
  };
  const field = (label, node) =>
    React.createElement("label", { style: { display: "block", margin: "4px 0" } }, `${label} `, node);
  return React.createElement(
    "form",
    { onSubmit: submit, style: { borderTop: "1px solid #ddd", marginTop: 12, paddingTop: 8 } },
    React.createElement("h4", null, "New project"),
    field("Name", React.createElement("input", { value: name, onChange: (e) => setName(e.target.value), required: true })),
    field(
      "Target URL",
      React.createElement("input", { value: targetUrl, onChange: (e) => setTargetUrl(e.target.value), required: true }),
    ),
    field(
      "Mode",
      React.createElement(
        "select",
        { value: mode, onChange: (e) => setMode(e.target.value) },
        React.createElement("option", { value: "blackbox" }, "blackbox"),
        reposConnected ? React.createElement("option", { value: "whitebox" }, "whitebox") : null,
      ),
    ),
    mode === "whitebox"
      ? field(
          "Repo",
          React.createElement(
            "select",
            { value: repoRef, onChange: (e) => setRepoRef(e.target.value), required: true },
            React.createElement("option", { value: "" }, "Select a repo…"),
            repos.map((r, i) =>
              React.createElement(
                "option",
                { key: i, value: r.fullName || r.full_name || r.id || r },
                r.fullName || r.full_name || r.name || String(r),
              ),
            ),
          ),
        )
      : null,
    reposConnected
      ? null
      : React.createElement(
          "p",
          { style: { color: "#777", fontSize: 12 } },
          "No GitHub repos connected — black-box only. Connect GitHub in the aegis app to enable white-box.",
        ),
    React.createElement("button", { type: "submit", disabled: busy }, busy ? "Creating…" : "Create project"),
  );
}
