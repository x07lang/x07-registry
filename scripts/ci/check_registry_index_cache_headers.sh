#!/usr/bin/env bash
set -euo pipefail

# Registry index entrypoint(s).
# Keep /index/ as the canonical entrypoint URL (it can 307 to catalog.json).
INDEX_ENTRY_URL="${X07_REGISTRY_INDEX_ENTRY_URL:-https://registry.x07.io/index/}"
INDEX_CATALOG_URL="${X07_REGISTRY_INDEX_CATALOG_URL:-https://registry.x07.io/index/catalog.json}"

# If you want to check fewer URLs, you can override:
#   X07_REGISTRY_INDEX_URLS="https://registry.x07.io/index/"
INDEX_URLS="${X07_REGISTRY_INDEX_URLS:-$INDEX_ENTRY_URL $INDEX_CATALOG_URL}"

_tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t x07cache)"
cleanup() { rm -rf "$_tmpdir"; }
trap cleanup EXIT

fetch_headers() {
  # Writes curl headers (incl redirects) into a file.
  # Using GET (not HEAD) avoids edge cases where CDNs treat HEAD differently.
  local url="$1"
  local out="$2"
  curl -sS -L -D "$out" -o /dev/null "$url"
}

# Parse the *final* response block from curl -D output and print:
# line1: status_code
# line2: etag_value (verbatim)
# line3: cache_control_value (verbatim)
parse_final_headers() {
  python3 - "$1" <<'PY'
import re, sys

p = sys.argv[1]
raw = open(p, "rb").read().decode("iso-8859-1", errors="replace")

# curl -D includes header blocks for redirects; blocks separated by blank line.
# We want the last non-empty block.
blocks = [b for b in re.split(r"\r?\n\r?\n", raw) if b.strip()]
if not blocks:
  print("0"); print(""); print(""); sys.exit(0)

last = blocks[-1].splitlines()
if not last:
  print("0"); print(""); print(""); sys.exit(0)

m = re.match(r"HTTP/\d+(?:\.\d+)?\s+(\d+)", last[0].strip())
status = int(m.group(1)) if m else 0

hdrs = {}
for line in last[1:]:
  if not line.strip():
    continue
  if ":" not in line:
    continue
  k, v = line.split(":", 1)
  k = k.strip().lower()
  v = v.strip()
  hdrs.setdefault(k, []).append(v)

etag = (hdrs.get("etag") or [""])[-1]
cc   = (hdrs.get("cache-control") or [""])[-1]

print(status)
print(etag)
print(cc)
PY
}

assert_cache_headers() {
  local url="$1"
  local hdr_file="$2"

  local meta status etag cc
  meta="$(parse_final_headers "$hdr_file")"
  status="$(printf '%s\n' "$meta" | sed -n '1p')"
  etag="$(printf '%s\n' "$meta" | sed -n '2p')"
  cc="$(printf '%s\n' "$meta" | sed -n '3p')"

  # Status
  if [[ "$status" != "200" ]]; then
    echo "ERROR: $url expected HTTP 200, got $status"
    echo "---- raw headers ----"
    cat "$hdr_file"
    exit 1
  fi

  # ETag presence (for conditional revalidation)
  if [[ -z "$etag" ]]; then
    echo "ERROR: $url missing ETag header"
    echo "---- raw headers ----"
    cat "$hdr_file"
    exit 1
  fi

  # Cache-Control presence
  if [[ -z "$cc" ]]; then
    echo "ERROR: $url missing Cache-Control header"
    echo "---- raw headers ----"
    cat "$hdr_file"
    exit 1
  fi

  # Validate Cache-Control semantics in a case-insensitive way (use python for portability).
  python3 - "$cc" <<'PY'
import sys

cc = sys.argv[1]
cc_l = cc.lower()

if "no-store" in cc_l:
    raise SystemExit("ERROR: Cache-Control contains no-store (disallowed for index endpoints): " + cc)

ok = ("max-age" in cc_l) or ("no-cache" in cc_l) or ("must-revalidate" in cc_l)
if not ok:
    raise SystemExit("ERROR: Cache-Control must include max-age=... or no-cache/must-revalidate: " + cc)
PY

  echo "OK: $url has ETag and acceptable Cache-Control: ETag=$etag; Cache-Control=$cc"
}

assert_if_none_match_304() {
  local url="$1"
  local etag="$2"
  local hdr_file="$3"

  curl -sS -L -D "$hdr_file" -o /dev/null -H "If-None-Match: $etag" "$url"

  local meta status
  meta="$(parse_final_headers "$hdr_file")"
  status="$(printf '%s\n' "$meta" | sed -n '1p')"

  if [[ "$status" != "304" ]]; then
    echo "ERROR: $url with If-None-Match expected HTTP 304, got $status"
    echo "ETag used: $etag"
    echo "---- raw headers ----"
    cat "$hdr_file"
    exit 1
  fi

  echo "OK: $url returns 304 Not Modified for If-None-Match"
}

echo "== registry index cache header checks =="
echo "URLs: $INDEX_URLS"

for url in $INDEX_URLS; do
  h1="$_tmpdir/hdr1.txt"
  h2="$_tmpdir/hdr2.txt"

  fetch_headers "$url" "$h1"

  meta="$(parse_final_headers "$h1")"
  etag="$(printf '%s\n' "$meta" | sed -n '2p')"

  assert_cache_headers "$url" "$h1"
  assert_if_none_match_304 "$url" "$etag" "$h2"
done

echo "PASS: registry index cache headers are OK"
