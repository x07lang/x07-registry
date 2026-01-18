#!/usr/bin/env bash
set -euo pipefail

BASE="${X07_REGISTRY_BASE:-https://registry.x07.io}"
INDEX_URL="${BASE%/}/index/"

echo "[x07-registry] smoke: ${INDEX_URL}"

# 1) Fast sanity: endpoint exists and responds (200 or redirect).
code="$(curl -sS -o /dev/null -w '%{http_code}' \
  --connect-timeout 5 --max-time 15 \
  "${INDEX_URL}")"

case "${code}" in
  200|301|302|303|307|308) ;;
  *)
    echo "[x07-registry] FAIL: ${INDEX_URL} returned HTTP ${code}" >&2
    exit 10
    ;;
esac

# 2) Contract check: follow redirects and validate the catalog JSON.
tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

curl -fsSL --retry 2 --retry-delay 1 --retry-all-errors \
  --connect-timeout 5 --max-time 20 \
  -o "${tmp}" \
  "${INDEX_URL}"

python3 - "${tmp}" <<'PY'
import json, sys

p = sys.argv[1]

try:
    with open(p, "rb") as f:
        doc = json.load(f)
except Exception as e:
    print("[x07-registry] FAIL: invalid JSON from /index/:", e, file=sys.stderr)
    sys.exit(20)

sv = doc.get("schema_version")
if sv != "x07.index-catalog@0.1.0":
    print(
        "[x07-registry] FAIL: schema_version={!r} (expected 'x07.index-catalog@0.1.0')".format(sv),
        file=sys.stderr,
    )
    sys.exit(21)

pkgs = doc.get("packages")
if not isinstance(pkgs, list) or len(pkgs) == 0:
    print("[x07-registry] FAIL: packages must be a non-empty list", file=sys.stderr)
    sys.exit(22)

for i, p in enumerate(pkgs):
    if not isinstance(p, dict):
        print("[x07-registry] FAIL: packages[{}] not an object".format(i), file=sys.stderr)
        sys.exit(23)
    name = p.get("name")
    if not isinstance(name, str) or not name:
        print(
            "[x07-registry] FAIL: packages[{}].name must be a non-empty string".format(i),
            file=sys.stderr,
        )
        sys.exit(24)
    latest = p.get("latest")
    if latest is not None and not isinstance(latest, str):
        print(
            "[x07-registry] FAIL: packages[{}].latest must be a string when present".format(i),
            file=sys.stderr,
        )
        sys.exit(25)

print("[x07-registry] OK: index catalog schema looks valid")
PY
