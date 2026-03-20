#!/usr/bin/env bash
set -euo pipefail

repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

step() {
  echo
  echo "==> $*"
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing tool: $1" >&2
    exit 2
  }
}

wait_for_http() {
  local url="$1"
  local label="$2"
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: ${label} did not become ready: ${url}" >&2
  return 1
}

root="$(repo_root)"
cd "$root"

need cargo
need curl
need docker
need python3

pg_container="x07-registry-ci-postgres-$$"
minio_container="x07-registry-ci-minio-$$"
pg_port="${X07_REGISTRY_TEST_DB_PORT:-55432}"
minio_port="${X07_REGISTRY_TEST_S3_PORT:-9000}"
db_url="${X07_REGISTRY_TEST_DATABASE_URL:-postgres://postgres:postgres@127.0.0.1:${pg_port}/postgres}"
minio_endpoint="${X07_REGISTRY_TEST_S3_ENDPOINT:-http://127.0.0.1:${minio_port}}"
run_s3="${X07_REGISTRY_TEST_RUN_S3:-1}"
started_pg=0
started_minio=0

cleanup() {
  if [[ "$started_minio" == "1" ]]; then
    docker rm -f "$minio_container" >/dev/null 2>&1 || true
  fi
  if [[ "$started_pg" == "1" ]]; then
    docker rm -f "$pg_container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ -z "${X07_REGISTRY_TEST_DATABASE_URL:-}" && -z "${DATABASE_URL:-}" ]]; then
  step "start postgres"
  docker run -d --name "$pg_container" \
    -e POSTGRES_PASSWORD=postgres \
    -p "${pg_port}:5432" \
    postgres:16 >/dev/null
  started_pg=1

  step "wait for postgres"
  for _ in $(seq 1 60); do
    if docker exec "$pg_container" pg_isready -U postgres >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  docker exec "$pg_container" pg_isready -U postgres >/dev/null 2>&1 || {
    docker logs "$pg_container" >&2 || true
    echo "ERROR: postgres did not become ready" >&2
    exit 1
  }
fi

export X07_REGISTRY_TEST_DATABASE_URL="$db_url"

step "validate openapi JSON"
python3 -m json.tool openapi/openapi.json >/dev/null

step "cargo test"
cargo test

if [[ "$run_s3" == "1" ]]; then
  step "start minio"
  docker run -d --name "$minio_container" \
    -p "${minio_port}:9000" \
    -e MINIO_ROOT_USER=minio \
    -e MINIO_ROOT_PASSWORD=minio123 \
    minio/minio:latest server /data >/dev/null
  started_minio=1

  step "wait for minio"
  wait_for_http "${minio_endpoint}/minio/health/ready" "minio" || {
    docker logs "$minio_container" >&2 || true
    exit 1
  }

  step "cargo test (s3 backend)"
  X07_REGISTRY_TEST_S3=1 \
  X07_REGISTRY_TEST_S3_ENDPOINT="${minio_endpoint}" \
  X07_REGISTRY_TEST_S3_REGION="${X07_REGISTRY_TEST_S3_REGION:-us-east-1}" \
  X07_REGISTRY_TEST_S3_BUCKET="${X07_REGISTRY_TEST_S3_BUCKET:-x07-registry-ci}" \
  X07_REGISTRY_TEST_S3_FORCE_PATH_STYLE="${X07_REGISTRY_TEST_S3_FORCE_PATH_STYLE:-true}" \
  X07_REGISTRY_TEST_S3_ACCESS_KEY_ID="${X07_REGISTRY_TEST_S3_ACCESS_KEY_ID:-minio}" \
  X07_REGISTRY_TEST_S3_SECRET_ACCESS_KEY="${X07_REGISTRY_TEST_S3_SECRET_ACCESS_KEY:-minio123}" \
  cargo test --test s3_backend
fi

echo
echo "ok: registry local checks passed"
