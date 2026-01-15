use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub data_dir: PathBuf,
    pub public_base: String,
    pub auth_token: Option<String>,
}

impl RegistryConfig {
    pub fn from_env() -> Self {
        let data_dir = std::env::var("X07_REGISTRY_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data"));
        let public_base = std::env::var("X07_REGISTRY_PUBLIC_BASE")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let auth_token = std::env::var("X07_REGISTRY_TOKEN").ok();
        Self {
            data_dir,
            public_base,
            auth_token,
        }
    }
}

#[derive(Debug, Clone)]
struct AppState {
    cfg: RegistryConfig,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

fn json_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (status, Json(ErrorResponse { code, message: message.into() })).into_response()
}

fn ok_json<T: Serialize>(value: T) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

fn validate_pkg_name(name: &str) -> Result<(), Response> {
    if name.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_NAME",
            "package name must be non-empty",
        ));
    }
    if !name.is_ascii() || name != name.to_ascii_lowercase() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_NAME",
            format!("package name must be lowercase ASCII: {name:?}"),
        ));
    }
    for b in name.as_bytes() {
        match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {}
            _ => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "X07REG_INVALID_NAME",
                    format!("package name contains invalid characters: {name:?}"),
                ))
            }
        }
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), Response> {
    if version.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_VERSION",
            "version must be non-empty",
        ));
    }
    if !version.is_ascii() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_VERSION",
            format!("version must be ASCII: {version:?}"),
        ));
    }
    for b in version.as_bytes() {
        match b {
            b'0'..=b'9' | b'.' | b'-' | b'+' | b'a'..=b'z' | b'A'..=b'Z' => {}
            _ => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "X07REG_INVALID_VERSION",
                    format!("version contains invalid characters: {version:?}"),
                ))
            }
        }
    }
    Ok(())
}

fn require_auth(headers: &HeaderMap, cfg: &RegistryConfig) -> Result<(), Response> {
    let Some(expected) = cfg.auth_token.as_deref() else {
        return Ok(());
    };
    let Some(h) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "X07REG_AUTH_REQUIRED",
            "missing Authorization header",
        ));
    };
    let raw = h.to_str().unwrap_or("");
    let token = raw.strip_prefix("Bearer ").unwrap_or("");
    if token != expected {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "X07REG_AUTH_INVALID",
            "invalid token",
        ));
    }
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[derive(Debug, Serialize)]
struct IndexConfig {
    dl: String,
    api: String,
    #[serde(rename = "auth-required")]
    auth_required: bool,
}

async fn index_config(State(state): State<Arc<AppState>>) -> Response {
    ok_json(IndexConfig {
        dl: format!("{}/v1/packages/", state.cfg.public_base.trim_end_matches('/')),
        api: format!("{}/v1/", state.cfg.public_base.trim_end_matches('/')),
        auth_required: state.cfg.auth_token.is_some(),
    })
}

async fn index_file(
    State(state): State<Arc<AppState>>,
    AxPath(path): AxPath<String>,
) -> Response {
    if path.is_empty() || path.contains("..") || path.contains('\\') {
        return json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INDEX_PATH_INVALID",
            "invalid index path",
        );
    }
    let full = state.cfg.data_dir.join("index").join(&path);
    let bytes = match std::fs::read(&full) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return json_error(StatusCode::NOT_FOUND, "X07REG_INDEX_NOT_FOUND", "not found")
        }
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_IO",
                format!("read {}: {err}", full.display()),
            )
        }
    };
    (StatusCode::OK, bytes).into_response()
}

#[derive(Debug, Serialize)]
struct TokenCheckResponse {
    ok: bool,
}

async fn token(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match require_auth(&headers, &state.cfg) {
        Ok(()) => ok_json(TokenCheckResponse { ok: true }),
        Err(resp) => resp,
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct PackageManifest {
    schema_version: String,
    name: String,
    version: String,
    module_root: String,
    modules: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PublishResponse {
    ok: bool,
    name: String,
    version: String,
    cksum: String,
    index_path: String,
}

async fn publish(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Body) -> Response {
    if let Err(resp) = require_auth(&headers, &state.cfg) {
        return resp;
    }

    let bytes: Bytes = match to_bytes(body, 64 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "X07REG_BODY_TOO_LARGE",
                format!("{err}"),
            )
        }
    };

    let cksum = sha256_hex(&bytes);
    let (manifest, manifest_bytes) = match read_package_manifest_from_tar(&bytes) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if manifest.schema_version.trim() != "x07.package@0.1.0" {
        return json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_PKG_SCHEMA_VERSION",
            format!("unsupported package schema_version: {:?}", manifest.schema_version),
        );
    }
    if let Err(resp) = validate_pkg_name(&manifest.name) {
        return resp;
    }
    if let Err(resp) = validate_version(&manifest.version) {
        return resp;
    }

    // Store artifact under dl-style path.
    let dl_path = state
        .cfg
        .data_dir
        .join("dl")
        .join(&manifest.name)
        .join(&manifest.version)
        .join("download");
    if dl_path.is_file() {
        return json_error(
            StatusCode::CONFLICT,
            "X07REG_ALREADY_PUBLISHED",
            "package version already exists",
        );
    }
    if let Some(parent) = dl_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_IO",
                format!("create {}: {err}", parent.display()),
            );
        }
    }
    if let Err(err) = std::fs::write(&dl_path, &bytes) {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_IO",
            format!("write {}: {err}", dl_path.display()),
        );
    }

    // Store manifest for metadata endpoint.
    let meta_path = state
        .cfg
        .data_dir
        .join("meta")
        .join(&manifest.name)
        .join(&manifest.version)
        .join("x07-package.json");
    if let Some(parent) = meta_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_IO",
                format!("create {}: {err}", parent.display()),
            );
        }
    }
    if let Err(err) = std::fs::write(&meta_path, &manifest_bytes) {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_IO",
            format!("write {}: {err}", meta_path.display()),
        );
    }

    let index_rel = match index_relative_path(&manifest.name) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let index_path = state.cfg.data_dir.join("index").join(&index_rel);
    if let Some(parent) = index_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_IO",
                format!("create {}: {err}", parent.display()),
            );
        }
    }

    let mut lines: Vec<IndexEntryLine> = Vec::new();
    if let Ok(existing) = std::fs::read_to_string(&index_path) {
        for (idx, line) in existing.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: IndexEntryLine = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(err) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "X07REG_INDEX_CORRUPT",
                        format!("parse {} line {}: {err}", index_path.display(), idx + 1),
                    )
                }
            };
            lines.push(entry);
        }
    }

    if lines
        .iter()
        .any(|e| e.name == manifest.name && e.version == manifest.version)
    {
        return json_error(
            StatusCode::CONFLICT,
            "X07REG_ALREADY_PUBLISHED",
            "package version already exists",
        );
    }

    lines.push(IndexEntryLine {
        schema_version: "x07.index-entry@0.1.0".to_string(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        cksum: cksum.clone(),
        yanked: false,
    });
    lines.sort_by(|a, b| a.version.as_bytes().cmp(b.version.as_bytes()));

    let mut out = String::new();
    for line in lines {
        out.push_str(&serde_json::to_string(&line).expect("serialize index line"));
        out.push('\n');
    }
    if let Err(err) = std::fs::write(&index_path, out.as_bytes()) {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_IO",
            format!("write {}: {err}", index_path.display()),
        );
    }

    ok_json(PublishResponse {
        ok: true,
        name: manifest.name,
        version: manifest.version,
        cksum,
        index_path: format!("/index/{index_rel}"),
    })
}

#[derive(Debug, Deserialize, Serialize)]
struct IndexEntryLine {
    schema_version: String,
    name: String,
    version: String,
    cksum: String,
    #[serde(default)]
    yanked: bool,
}

async fn download(
    State(state): State<Arc<AppState>>,
    AxPath((name, version)): AxPath<(String, String)>,
) -> Response {
    if let Err(resp) = validate_pkg_name(&name) {
        return resp;
    }
    if let Err(resp) = validate_version(&version) {
        return resp;
    }
    let path = state
        .cfg
        .data_dir
        .join("dl")
        .join(&name)
        .join(&version)
        .join("download");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found")
        }
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_IO",
                format!("read {}: {err}", path.display()),
            )
        }
    };
    (StatusCode::OK, bytes).into_response()
}

#[derive(Debug, Serialize)]
struct PackageMetadataResponse {
    ok: bool,
    package: PackageManifest,
    cksum: String,
}

async fn package_metadata(
    State(state): State<Arc<AppState>>,
    AxPath((name, version)): AxPath<(String, String)>,
) -> Response {
    if let Err(resp) = validate_pkg_name(&name) {
        return resp;
    }
    if let Err(resp) = validate_version(&version) {
        return resp;
    }

    let meta_path = state
        .cfg
        .data_dir
        .join("meta")
        .join(&name)
        .join(&version)
        .join("x07-package.json");
    let bytes = match std::fs::read(&meta_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found")
        }
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_IO",
                format!("read {}: {err}", meta_path.display()),
            )
        }
    };
    let pkg: PackageManifest = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_META_CORRUPT",
                format!("parse {}: {err}", meta_path.display()),
            )
        }
    };

    let index_rel = match index_relative_path(&name) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let index_path = state.cfg.data_dir.join("index").join(&index_rel);
    let index_text = match std::fs::read_to_string(&index_path) {
        Ok(s) => s,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found")
        }
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_IO",
                format!("read {}: {err}", index_path.display()),
            )
        }
    };
    let mut cksum = None;
    for line in index_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<IndexEntryLine>(line) {
            if entry.name == name && entry.version == version {
                cksum = Some(entry.cksum);
                break;
            }
        }
    }
    let Some(cksum) = cksum else {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_INDEX_CORRUPT",
            "index entry missing",
        );
    };

    ok_json(PackageMetadataResponse {
        ok: true,
        package: pkg,
        cksum,
    })
}

pub fn app() -> Router {
    app_with_config(RegistryConfig::from_env())
}

pub fn app_with_config(cfg: RegistryConfig) -> Router {
    let state = Arc::new(AppState { cfg });
    Router::new()
        .route("/healthz", get(healthz))
        .route("/index/config.json", get(index_config))
        .route("/index/{*path}", get(index_file))
        .route("/v1/auth/token", post(token))
        .route("/v1/packages/publish", post(publish))
        .route("/v1/packages/{name}/{version}/download", get(download))
        .route("/v1/packages/{name}/{version}/metadata", get(package_metadata))
        .with_state(state)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn read_package_manifest_from_tar(tar_bytes: &[u8]) -> Result<(PackageManifest, Vec<u8>), Response> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    for entry in archive.entries().map_err(|e| {
        json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_BAD_ARCHIVE",
            format!("read tar entries: {e}"),
        )
    })? {
        let mut entry = entry.map_err(|e| {
            json_error(
                StatusCode::BAD_REQUEST,
                "X07REG_BAD_ARCHIVE",
                format!("read tar entry: {e}"),
            )
        })?;
        let path = entry.path().map_err(|e| {
            json_error(
                StatusCode::BAD_REQUEST,
                "X07REG_BAD_ARCHIVE",
                format!("read tar entry path: {e}"),
            )
        })?;
        if path.as_ref() == Path::new("x07-package.json") {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| json_error(StatusCode::BAD_REQUEST, "X07REG_BAD_ARCHIVE", e.to_string()))?;
            let pkg: PackageManifest = serde_json::from_slice(&bytes).map_err(|e| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "X07REG_BAD_MANIFEST",
                    format!("parse x07-package.json: {e}"),
                )
            })?;
            return Ok((pkg, bytes));
        }
    }
    Err(json_error(
        StatusCode::BAD_REQUEST,
        "X07REG_BAD_ARCHIVE",
        "missing x07-package.json",
    ))
}

fn index_relative_path(name: &str) -> Result<String, Response> {
    validate_pkg_name(name)?;
    let bytes = name.as_bytes();
    let shard = match bytes.len() {
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", &name[0..1]),
        _ => format!("{}/{}", &name[0..2], &name[2..4]),
    };
    Ok(format!("{shard}/{name}"))
}
