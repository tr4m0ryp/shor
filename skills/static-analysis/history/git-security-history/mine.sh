#!/usr/bin/env bash
# git-security-history — mine the cloned repo's history for security/fix commits
# and emit historical_signal.json. LOCAL-ONLY: git + filesystem, no network.
set -euo pipefail

REPO="."
OUT=""
OSV=""
GITLEAKS=""

while [ "$#" -gt 0 ]; do
	case "$1" in
		--repo) REPO="$2"; shift 2;;
		--out) OUT="$2"; shift 2;;
		--osv) OSV="$2"; shift 2;;
		--gitleaks) GITLEAKS="$2"; shift 2;;
		-h|--help)
			echo "usage: mine.sh --repo DIR [--out FILE] [--osv FILE] [--gitleaks FILE]"
			exit 0;;
		*) echo "unknown arg: $1" >&2; exit 2;;
	esac
done

[ -n "$OUT" ] || OUT="$REPO/.storron/deliverables/historical_signal.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v python3 >/dev/null 2>&1 || { echo "python3 required" >&2; exit 3; }

# Security / CVE / fix patterns mapped to touched files. Read-only history walk;
# `|| true` so an empty match set (or a shallow/non-repo) still emits valid JSON.
PATTERN="secur|vuln|CVE-|XSS|SQLi|injection|auth bypass|RCE|SSRF|IDOR|sanitiz"
git -C "$REPO" log --all -i -E --no-merges --date=short \
	--grep="$PATTERN" --name-only \
	--pretty=format:"@@COMMIT@@%x1f%H%x1f%cd%x1f%s" 2>/dev/null \
	| python3 "$SCRIPT_DIR/assemble.py" \
		--out "$OUT" \
		${OSV:+--osv "$OSV"} \
		${GITLEAKS:+--gitleaks "$GITLEAKS"} \
	|| true

echo "wrote $OUT"
