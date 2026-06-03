#!/bin/sh
# Shor container entrypoint — ported from storron infra/docker/entrypoint.sh,
# de-Tor'd and de-privileged.
#
# What changed vs storron (LAUNCH-SPEC §1, §7 Phase 1, ADR-051):
#   - REMOVED all Tor/onion plumbing. There is no torsocks, no SOCKS bootstrap,
#     no `ensureTorReady`; Shor is direct clearnet egress only. Any TOR_* /
#     TORSOCKS_* env is intentionally ignored.
#   - REMOVED the STORRON_HOST_UID/GID userdel/useradd remap + `su pentest`.
#     storron remapped the in-container user to the host user so host-Docker
#     bind mounts stayed writable. Shor drops host-`docker run` for a Cloud Run
#     Job per scan (ADR-051): the image already runs as a fixed nonroot uid
#     (65532) and working dirs are ephemeral, so no remap is needed or wanted
#     (remapping needs root; we run unprivileged).
#
# Responsibilities now:
#   - Make the per-run working directory current and writable.
#   - exec the command (default `bash`; the worker entrypoint in production).

set -eu

# Per-run ephemeral workdir. The orchestrator may mount one at SHOR_WORKDIR;
# otherwise fall back to /work (created in the image) or a tmp dir.
WORKDIR="${SHOR_WORKDIR:-/work}"
if ! cd "$WORKDIR" 2>/dev/null; then
  WORKDIR="$(mktemp -d 2>/dev/null || echo /tmp)"
  cd "$WORKDIR"
fi
export SHOR_WORKDIR="$WORKDIR"

# Caches/config under a writable HOME (set in the image to /tmp).
mkdir -p "${XDG_CACHE_HOME:-/tmp/.cache}" "${XDG_CONFIG_HOME:-/tmp/.config}" 2>/dev/null || true

# Hand off to the command. With no args, drop into an interactive shell.
if [ "$#" -eq 0 ]; then
  set -- bash
fi
exec "$@"
