#!/usr/bin/env python3
"""Assemble historical_signal.json from a `git log` stream + optional reports.

Reads a `git log --name-only --pretty=format:@@COMMIT@@<US>sha<US>date<US>subject`
stream on stdin, groups touched files into ranked hot files, folds optional
osv-scanner (dependency CVEs) and gitleaks (history secrets) JSON reports, and
writes the pinned schema. LOCAL-ONLY: stdlib only, no network, secrets redacted.
"""
import argparse
import json
import os
import re
import sys

MARKER = "@@COMMIT@@"
US = "\x1f"

CAP_HOT_FILES = 40
CAP_COMMITS_PER_FILE = 8
CAP_DEP_CVES = 60
CAP_CVES_PER_FILE = 12
CAP_SUBJECT_LEN = 200

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SECRET_RES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
SECRET_KV_RE = re.compile(
    r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key)\b"
    r"(\s*[:=]\s*)['\"]?[^\s'\"]{6,}"
)


def redact(text):
    out = text
    for pat in SECRET_RES:
        out = pat.sub("[REDACTED]", out)
    return SECRET_KV_RE.sub(r"\1\2[REDACTED]", out)


def cves_in(text):
    seen = []
    for m in CVE_RE.findall(text):
        u = m.upper()
        if u not in seen:
            seen.append(u)
    return seen


def add_commit(files, path, sha, date, subject):
    entry = files.setdefault(path, {"commits": [], "shas": set()})
    if not sha or sha in entry["shas"]:
        return
    entry["shas"].add(sha)
    entry["commits"].append(
        {"sha": sha, "date": date, "subject": redact(subject)[:CAP_SUBJECT_LEN]}
    )


def parse_git_stream(stream, files):
    cur = None
    for raw in stream.splitlines():
        line = raw.rstrip("\n")
        if line.startswith(MARKER):
            parts = line.split(US)
            cur = {
                "sha": parts[1] if len(parts) > 1 else "",
                "date": parts[2] if len(parts) > 2 else "",
                "subject": parts[3] if len(parts) > 3 else "",
            }
        elif line.strip() and cur is not None:
            add_commit(files, line.strip(), cur["sha"], cur["date"], cur["subject"])


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def fold_gitleaks(path, files):
    data = load_json(path)
    if not isinstance(data, list):
        return
    for hit in data:
        if not isinstance(hit, dict):
            continue
        f = hit.get("File") or hit.get("file")
        if not f:
            continue
        rule = hit.get("RuleID") or hit.get("rule") or "secret"
        sha = (hit.get("Commit") or hit.get("commit") or "")[:12]
        date = (hit.get("Date") or hit.get("date") or "")[:10]
        add_commit(files, f, sha or rule, date, "history secret (%s)" % rule)


def osv_severity(vuln):
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict) and db.get("severity"):
        return str(db["severity"])
    sev = vuln.get("severity") or []
    if isinstance(sev, list) and sev:
        first = sev[0]
        if isinstance(first, dict):
            return str(first.get("score") or first.get("type") or "unknown")
    return "unknown"


def osv_fixed(vuln):
    for aff in vuln.get("affected") or []:
        for rng in (aff or {}).get("ranges") or []:
            for ev in (rng or {}).get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    return str(ev["fixed"])
    return ""


def fold_osv(path):
    data = load_json(path)
    out, seen = [], set()
    if not isinstance(data, dict):
        return out
    for result in data.get("results") or []:
        for pkg in (result or {}).get("packages") or []:
            info = (pkg or {}).get("package") or {}
            name = info.get("name") or ""
            version = info.get("version") or "unknown"
            for vuln in (pkg or {}).get("vulnerabilities") or []:
                vid = vuln.get("id") or ""
                if not name or not vid:
                    continue
                key = "%s@%s:%s" % (name, version, vid)
                if key in seen:
                    continue
                seen.add(key)
                rec = {
                    "package": name,
                    "version": version,
                    "id": vid,
                    "severity": osv_severity(vuln),
                }
                fixed = osv_fixed(vuln)
                if fixed:
                    rec["fixedVersion"] = fixed
                out.append(rec)
                if len(out) >= CAP_DEP_CVES:
                    return out
    return out


def build_hot_files(files):
    ranked = sorted(files.items(), key=lambda kv: len(kv[1]["commits"]), reverse=True)
    out = []
    for path, entry in ranked[:CAP_HOT_FILES]:
        commits = entry["commits"][:CAP_COMMITS_PER_FILE]
        cves = []
        for c in commits:
            for cve in cves_in(c["subject"]):
                if cve not in cves:
                    cves.append(cve)
        hot = {"file": path, "commits": commits}
        if cves:
            hot["cves"] = cves[:CAP_CVES_PER_FILE]
        out.append(hot)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--osv")
    ap.add_argument("--gitleaks")
    args = ap.parse_args()

    files = {}
    parse_git_stream(sys.stdin.read(), files)
    if args.gitleaks:
        fold_gitleaks(args.gitleaks, files)

    signal = {
        "hotFiles": build_hot_files(files),
        "depCves": fold_osv(args.osv) if args.osv else [],
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(signal, fh, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main()
