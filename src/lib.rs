use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path as AxPath, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use rand::RngCore;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

type ApiError = Box<Response>;
type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Clone)]
pub struct RegistryS3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: String,
    pub prefix: String,
    pub force_path_style: bool,
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Debug, Clone)]
pub enum RegistryStorageConfig {
    Filesystem { data_dir: PathBuf },
    S3(RegistryS3Config),
}

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub public_base: String,
    pub database_url: String,
    pub database_schema: String,
    pub bootstrap_token: Option<String>,
    pub cors_origins: Vec<String>,
    pub storage: RegistryStorageConfig,
}

impl RegistryConfig {
    pub fn from_env() -> Self {
        let public_base = std::env::var("X07_REGISTRY_PUBLIC_BASE")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let database_url = std::env::var("X07_REGISTRY_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgres://x07:x07@127.0.0.1:5432/x07_registry".to_string());
        let database_schema = std::env::var("X07_REGISTRY_DATABASE_SCHEMA")
            .unwrap_or_else(|_| "public".to_string());
        let bootstrap_token = std::env::var("X07_REGISTRY_BOOTSTRAP_TOKEN").ok();
        let cors_origins = std::env::var("X07_REGISTRY_CORS_ORIGINS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let storage = match std::env::var("X07_REGISTRY_STORAGE")
            .unwrap_or_else(|_| "fs".to_string())
            .as_str()
        {
            "fs" | "filesystem" => {
                let data_dir = std::env::var("X07_REGISTRY_DATA_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("data"));
                RegistryStorageConfig::Filesystem { data_dir }
            }
            "s3" => {
                let bucket = std::env::var("X07_REGISTRY_S3_BUCKET")
                    .expect("missing X07_REGISTRY_S3_BUCKET");
                let region = std::env::var("X07_REGISTRY_S3_REGION")
                    .expect("missing X07_REGISTRY_S3_REGION");
                let endpoint = std::env::var("X07_REGISTRY_S3_ENDPOINT")
                    .expect("missing X07_REGISTRY_S3_ENDPOINT");
                let prefix = std::env::var("X07_REGISTRY_S3_PREFIX").unwrap_or_default();
                let force_path_style = std::env::var("X07_REGISTRY_S3_FORCE_PATH_STYLE")
                    .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"));

                let access_key_id = std::env::var("X07_REGISTRY_S3_ACCESS_KEY_ID")
                    .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
                    .expect("missing X07_REGISTRY_S3_ACCESS_KEY_ID/AWS_ACCESS_KEY_ID");
                let secret_access_key = std::env::var("X07_REGISTRY_S3_SECRET_ACCESS_KEY")
                    .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
                    .expect("missing X07_REGISTRY_S3_SECRET_ACCESS_KEY/AWS_SECRET_ACCESS_KEY");

                RegistryStorageConfig::S3(RegistryS3Config {
                    bucket,
                    region,
                    endpoint,
                    prefix,
                    force_path_style,
                    access_key_id,
                    secret_access_key,
                })
            }
            other => panic!("unsupported X07_REGISTRY_STORAGE={other:?}"),
        };
        Self {
            public_base,
            database_url,
            database_schema,
            bootstrap_token,
            cors_origins,
            storage,
        }
    }
}

#[derive(Debug)]
struct StoreError {
    message: String,
}

impl StoreError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

#[derive(Clone)]
struct FsStore {
    root: PathBuf,
}

impl FsStore {
    fn full_path(&self, key: &str) -> Result<PathBuf, StoreError> {
        if key.is_empty() || key.starts_with('/') || key.contains("..") || key.contains('\\') {
            return Err(StoreError::new(format!("invalid key: {key:?}")));
        }
        Ok(self.root.join(key))
    }
}

#[derive(Clone)]
struct S3Store {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

impl S3Store {
    fn normalize_prefix(prefix: &str) -> String {
        let trimmed = prefix.trim().trim_matches('/');
        if trimmed.is_empty() {
            return String::new();
        }
        format!("{trimmed}/")
    }

    fn object_key(&self, key: &str) -> Result<String, StoreError> {
        if key.is_empty() || key.starts_with('/') || key.contains("..") || key.contains('\\') {
            return Err(StoreError::new(format!("invalid key: {key:?}")));
        }
        Ok(format!("{}{}", self.prefix, key))
    }
}

#[derive(Clone)]
enum Store {
    Fs(FsStore),
    S3(S3Store),
}

impl Store {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        match self {
            Store::Fs(fs) => {
                let path = fs.full_path(key)?;
                match tokio::fs::read(&path).await {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(err) => Err(StoreError::new(format!("read {}: {err}", path.display()))),
                }
            }
            Store::S3(s3) => {
                let object_key = s3.object_key(key)?;
                match s3
                    .client
                    .get_object()
                    .bucket(&s3.bucket)
                    .key(&object_key)
                    .send()
                    .await
                {
                    Ok(output) => {
                        let data = output.body.collect().await.map_err(|err| {
                            StoreError::new(format!("read s3://{}/{object_key}: {err}", s3.bucket))
                        })?;
                        Ok(Some(data.into_bytes().to_vec()))
                    }
                    Err(err) => {
                        if let aws_sdk_s3::error::SdkError::ServiceError(service_err) = &err {
                            if service_err.err().is_no_such_key() {
                                return Ok(None);
                            }
                        }
                        Err(StoreError::new(format!(
                            "get s3://{}/{object_key}: {err}",
                            s3.bucket
                        )))
                    }
                }
            }
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, StoreError> {
        match self {
            Store::Fs(fs) => {
                let path = fs.full_path(key)?;
                match tokio::fs::metadata(&path).await {
                    Ok(_) => Ok(true),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(err) => Err(StoreError::new(format!(
                        "metadata {}: {err}",
                        path.display()
                    ))),
                }
            }
            Store::S3(s3) => {
                let object_key = s3.object_key(key)?;
                match s3
                    .client
                    .head_object()
                    .bucket(&s3.bucket)
                    .key(&object_key)
                    .send()
                    .await
                {
                    Ok(_) => Ok(true),
                    Err(err) => {
                        if let aws_sdk_s3::error::SdkError::ServiceError(service_err) = &err {
                            if service_err.err().is_not_found() {
                                return Ok(false);
                            }
                        }
                        Err(StoreError::new(format!(
                            "head s3://{}/{object_key}: {err}",
                            s3.bucket
                        )))
                    }
                }
            }
        }
    }

    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        content_type: Option<&'static str>,
    ) -> Result<(), StoreError> {
        match self {
            Store::Fs(fs) => {
                let path = fs.full_path(key)?;
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await.map_err(|err| {
                        StoreError::new(format!("create {}: {err}", parent.display()))
                    })?;
                }
                tokio::fs::write(&path, &bytes)
                    .await
                    .map_err(|err| StoreError::new(format!("write {}: {err}", path.display())))?;
                Ok(())
            }
            Store::S3(s3) => {
                let object_key = s3.object_key(key)?;
                let mut req = s3
                    .client
                    .put_object()
                    .bucket(&s3.bucket)
                    .key(&object_key)
                    .body(aws_sdk_s3::primitives::ByteStream::from(bytes));
                if let Some(ct) = content_type {
                    req = req.content_type(ct);
                }
                req.send().await.map_err(|err| {
                    StoreError::new(format!("put s3://{}/{object_key}: {err}", s3.bucket))
                })?;
                Ok(())
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        match self {
            Store::Fs(fs) => {
                let path = fs.full_path(key)?;
                match tokio::fs::remove_file(&path).await {
                    Ok(()) => Ok(()),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(err) => Err(StoreError::new(format!(
                        "remove {}: {err}",
                        path.display()
                    ))),
                }
            }
            Store::S3(s3) => {
                let object_key = s3.object_key(key)?;
                s3.client
                    .delete_object()
                    .bucket(&s3.bucket)
                    .key(&object_key)
                    .send()
                    .await
                    .map_err(|err| {
                        StoreError::new(format!(
                            "delete s3://{}/{object_key}: {err}",
                            s3.bucket
                        ))
                    })?;
                Ok(())
            }
        }
    }
}

struct AppState {
    cfg: RegistryConfig,
    store: Store,
    db: PgPool,
    publish_lock: Mutex<()>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

fn json_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            code,
            message: message.into(),
        }),
    )
        .into_response()
}

fn boxed_json_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> ApiError {
    Box::new(json_error(status, code, message))
}

fn ok_json<T: Serialize>(value: T) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

fn validate_pkg_name(name: &str) -> ApiResult<()> {
    if name.is_empty() {
        return Err(boxed_json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_NAME",
            "package name must be non-empty",
        ));
    }
    if !name.is_ascii() || name != name.to_ascii_lowercase() {
        return Err(boxed_json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_NAME",
            format!("package name must be lowercase ASCII: {name:?}"),
        ));
    }
    for b in name.as_bytes() {
        match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {}
            _ => {
                return Err(boxed_json_error(
                    StatusCode::BAD_REQUEST,
                    "X07REG_INVALID_NAME",
                    format!("package name contains invalid characters: {name:?}"),
                ))
            }
        }
    }
    Ok(())
}

fn validate_version(version: &str) -> ApiResult<()> {
    if version.is_empty() {
        return Err(boxed_json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_VERSION",
            "version must be non-empty",
        ));
    }
    if !version.is_ascii() {
        return Err(boxed_json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_VERSION",
            format!("version must be ASCII: {version:?}"),
        ));
    }
    if let Err(err) = Version::parse(version) {
        return Err(boxed_json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INVALID_VERSION",
            format!("version must be valid semver: {err}"),
        ));
    }
    Ok(())
}

fn is_valid_db_schema_name(schema: &str) -> bool {
    if schema.is_empty() || !schema.is_ascii() || schema != schema.to_ascii_lowercase() {
        return false;
    }
    let mut chars = schema.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !matches!(first, 'a'..='z' | '_') {
        return false;
    }
    chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

#[derive(Debug, Clone)]
struct AuthContext {
    token_id: Uuid,
    user_id: Uuid,
    user_handle: String,
    scopes: Vec<String>,
}

fn bearer_token<'a>(headers: &'a HeaderMap) -> Option<&'a str> {
    let h = headers.get(axum::http::header::AUTHORIZATION)?;
    let raw = h.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
}

fn require_bootstrap_auth(headers: &HeaderMap, cfg: &RegistryConfig) -> ApiResult<()> {
    let Some(expected) = cfg.bootstrap_token.as_deref() else {
        return Err(boxed_json_error(
            StatusCode::FORBIDDEN,
            "X07REG_BOOTSTRAP_DISABLED",
            "bootstrap is not enabled",
        ));
    };
    let Some(token) = bearer_token(headers) else {
        return Err(boxed_json_error(
            StatusCode::UNAUTHORIZED,
            "X07REG_AUTH_REQUIRED",
            "missing Authorization header",
        ));
    };
    if token != expected {
        return Err(boxed_json_error(
            StatusCode::UNAUTHORIZED,
            "X07REG_AUTH_INVALID",
            "invalid token",
        ));
    }
    Ok(())
}

fn require_scope(auth: &AuthContext, scope: &str) -> ApiResult<()> {
    if auth.scopes.iter().any(|s| s == scope) {
        return Ok(());
    }
    Err(boxed_json_error(
        StatusCode::FORBIDDEN,
        "X07REG_FORBIDDEN",
        format!("missing scope: {scope}"),
    ))
}

async fn require_token(
    headers: &HeaderMap,
    state: &AppState,
    required_scopes: &[&str],
) -> ApiResult<AuthContext> {
    let Some(token) = bearer_token(headers) else {
        return Err(boxed_json_error(
            StatusCode::UNAUTHORIZED,
            "X07REG_AUTH_REQUIRED",
            "missing Authorization header",
        ));
    };
    let token_hash = sha256_hex(token.as_bytes());

    #[derive(sqlx::FromRow)]
    struct TokenRow {
        id: Uuid,
        user_id: Uuid,
        handle: String,
        scopes: Vec<String>,
        revoked_at: Option<DateTime<Utc>>,
    }

    let row: Option<TokenRow> = sqlx::query_as(
        r#"
        SELECT t.id, t.user_id, u.handle, t.scopes, t.revoked_at
        FROM tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| {
        boxed_json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("db query failed: {err}"),
        )
    })?;

    let Some(row) = row else {
        return Err(boxed_json_error(
            StatusCode::UNAUTHORIZED,
            "X07REG_AUTH_INVALID",
            "invalid token",
        ));
    };
    if row.revoked_at.is_some() {
        return Err(boxed_json_error(
            StatusCode::UNAUTHORIZED,
            "X07REG_AUTH_INVALID",
            "token revoked",
        ));
    }

    let auth = AuthContext {
        token_id: row.id,
        user_id: row.user_id,
        user_handle: row.handle,
        scopes: row.scopes,
    };
    for scope in required_scopes {
        require_scope(&auth, scope)?;
    }

    sqlx::query("UPDATE tokens SET last_used_at = now() WHERE id = $1")
        .bind(auth.token_id)
        .execute(&state.db)
        .await
        .map_err(|err| {
            boxed_json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("db update failed: {err}"),
            )
        })?;

    Ok(auth)
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
    sparse: bool,
}

async fn index_config(State(state): State<Arc<AppState>>) -> Response {
    ok_json(IndexConfig {
        dl: format!(
            "{}/v1/packages/",
            state.cfg.public_base.trim_end_matches('/')
        ),
        api: format!("{}/v1/", state.cfg.public_base.trim_end_matches('/')),
        auth_required: false,
        sparse: true,
    })
}

async fn index_file(State(state): State<Arc<AppState>>, AxPath(path): AxPath<String>) -> Response {
    if path.is_empty() || path.contains("..") || path.contains('\\') {
        return json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INDEX_PATH_INVALID",
            "invalid index path",
        );
    }

    if path == "catalog.json" {
        #[derive(sqlx::FromRow)]
        struct CatalogRow {
            name: String,
            latest_version: Option<String>,
        }

        let rows: Vec<CatalogRow> = match sqlx::query_as(
            "SELECT name, latest_version FROM packages ORDER BY name ASC",
        )
        .fetch_all(&state.db)
        .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("select catalog: {err}"),
                )
            }
        };
        let catalog = IndexCatalog {
            schema_version: "x07.index-catalog@0.1.0".to_string(),
            packages: rows
                .into_iter()
                .map(|r| IndexCatalogPackage {
                    name: r.name,
                    latest: r.latest_version,
                })
                .collect(),
        };
        let mut body = serde_json::to_string(&catalog).expect("serialize catalog");
        body.push('\n');
        return (StatusCode::OK, body).into_response();
    }

    let Some(name) = path.split('/').last().filter(|v| !v.is_empty()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INDEX_PATH_INVALID",
            "invalid index path",
        );
    };
    if let Err(resp) = validate_pkg_name(name) {
        return *resp;
    }
    let expected_path = match index_relative_path(name) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    if expected_path != path {
        return json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_INDEX_PATH_INVALID",
            "invalid index path",
        );
    }

    #[derive(sqlx::FromRow)]
    struct VersionRow {
        version: String,
        cksum: String,
        yanked: bool,
    }

    let mut versions: Vec<VersionRow> = match sqlx::query_as(
        r#"
        SELECT pv.version, pv.cksum, pv.yanked
        FROM package_versions pv
        JOIN packages p ON p.id = pv.package_id
        WHERE p.name = $1
        "#,
    )
    .bind(name)
    .fetch_all(&state.db)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select index entries: {err}"),
            )
        }
    };
    if versions.is_empty() {
        return json_error(StatusCode::NOT_FOUND, "X07REG_INDEX_NOT_FOUND", "not found");
    }

    versions.sort_by(|a, b| {
        let va = Version::parse(&a.version);
        let vb = Version::parse(&b.version);
        match (va, vb) {
            (Ok(va), Ok(vb)) => va.cmp(&vb),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => a.version.cmp(&b.version),
        }
    });

    let mut out = String::new();
    for row in &versions {
        let line = IndexEntryLine {
            schema_version: "x07.index-entry@0.1.0".to_string(),
            name: name.to_string(),
            version: row.version.clone(),
            cksum: row.cksum.clone(),
            yanked: row.yanked,
        };
        out.push_str(&serde_json::to_string(&line).expect("serialize index entry"));
        out.push('\n');
    }
    (StatusCode::OK, out).into_response()
}

#[derive(Debug, Serialize)]
struct TokenCheckResponse {
    ok: bool,
}

async fn token(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match require_token(&headers, state.as_ref(), &[]).await {
        Ok(_) => ok_json(TokenCheckResponse { ok: true }),
        Err(resp) => *resp,
    }
}

#[derive(Debug, Serialize)]
struct AccountResponse {
    ok: bool,
    user_id: Uuid,
    handle: String,
    token_id: Uuid,
    scopes: Vec<String>,
}

async fn account(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = match require_token(&headers, state.as_ref(), &[]).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    ok_json(AccountResponse {
        ok: true,
        user_id: auth.user_id,
        handle: auth.user_handle,
        token_id: auth.token_id,
        scopes: auth.scopes,
    })
}

#[derive(Debug, Deserialize)]
struct BootstrapRequest {
    handle: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BootstrapResponse {
    ok: bool,
    user_id: Uuid,
    handle: String,
    token_id: Uuid,
    token: String,
    scopes: Vec<String>,
}

async fn admin_bootstrap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BootstrapRequest>,
) -> Response {
    if let Err(resp) = require_bootstrap_auth(&headers, &state.cfg) {
        return *resp;
    }

    let handle = req.handle.trim().to_ascii_lowercase();
    if let Err(resp) = validate_pkg_name(&handle) {
        return *resp;
    }
    let label = req.label.trim().to_string();

    let mut scopes = req.scopes;
    if scopes.is_empty() {
        scopes = vec![
            "admin".to_string(),
            "publish".to_string(),
            "token.manage".to_string(),
            "owner.manage".to_string(),
        ];
    }
    for scope in &scopes {
        match scope.as_str() {
            "admin" | "publish" | "token.manage" | "owner.manage" => {}
            _ => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "X07REG_SCOPE_INVALID",
                    format!("unsupported scope: {scope:?}"),
                )
            }
        }
    }
    scopes.sort();
    scopes.dedup();

    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("begin transaction: {err}"),
            )
        }
    };

    let user_id: Uuid = match sqlx::query_scalar(
        "INSERT INTO users(handle) VALUES ($1) ON CONFLICT(handle) DO UPDATE SET handle = EXCLUDED.handle RETURNING id",
    )
    .bind(&handle)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("upsert user: {err}"),
            )
        }
    };

    let (token_id, token) = {
        let mut rng = rand::rngs::OsRng;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            if attempt > 10 {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_TOKEN_GENERATION_FAILED",
                    "failed to allocate a unique token",
                );
            }
            let mut raw = [0u8; 32];
            rng.fill_bytes(&mut raw);
            let token = format!("x07t_{}", sha256_hex(&raw));
            let token_hash = sha256_hex(token.as_bytes());

            let inserted: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
                "INSERT INTO tokens(user_id, token_hash, label, scopes) VALUES ($1, $2, $3, $4) RETURNING id",
            )
            .bind(user_id)
            .bind(&token_hash)
            .bind(&label)
            .bind(&scopes)
            .fetch_one(&mut *tx)
            .await;
            match inserted {
                Ok(id) => break (id, token),
                Err(sqlx::Error::Database(db_err))
                    if db_err.code().as_deref() == Some("23505") =>
                {
                    continue
                }
                Err(err) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "X07REG_DB",
                        format!("insert token: {err}"),
                    )
                }
            }
        }
    };

    if let Err(err) = sqlx::query(
        "INSERT INTO audit_events(actor_user_id, actor_token_id, action, details) VALUES ($1, $2, 'token_created', $3)",
    )
    .bind(user_id)
    .bind(token_id)
    .bind(serde_json::json!({ "label": &label, "scopes": &scopes }))
    .execute(&mut *tx)
    .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert audit: {err}"),
        );
    }

    if let Err(err) = tx.commit().await {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("commit: {err}"),
        );
    }

    ok_json(BootstrapResponse {
        ok: true,
        user_id,
        handle,
        token_id,
        token,
        scopes,
    })
}

#[derive(Debug, Serialize)]
struct TokenInfo {
    id: Uuid,
    label: String,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct TokenListResponse {
    ok: bool,
    tokens: Vec<TokenInfo>,
}

async fn tokens_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = match require_token(&headers, state.as_ref(), &["token.manage"]).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    #[derive(sqlx::FromRow)]
    struct TokenRow {
        id: Uuid,
        label: String,
        scopes: Vec<String>,
        created_at: DateTime<Utc>,
        last_used_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
    }

    let rows: Vec<TokenRow> = match sqlx::query_as(
        "SELECT id, label, scopes, created_at, last_used_at, revoked_at FROM tokens WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select tokens: {err}"),
            )
        }
    };

    ok_json(TokenListResponse {
        ok: true,
        tokens: rows
            .into_iter()
            .map(|r| TokenInfo {
                id: r.id,
                label: r.label,
                scopes: r.scopes,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
                revoked_at: r.revoked_at,
            })
            .collect(),
    })
}

#[derive(Debug, Deserialize)]
struct TokenCreateRequest {
    #[serde(default)]
    label: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TokenCreateResponse {
    ok: bool,
    token_id: Uuid,
    token: String,
    scopes: Vec<String>,
}

async fn token_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TokenCreateRequest>,
) -> Response {
    let auth = match require_token(&headers, state.as_ref(), &["token.manage"]).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    let label = req.label.trim().to_string();
    let mut scopes = req.scopes;
    if scopes.is_empty() {
        scopes.push("publish".to_string());
    }
    for scope in &scopes {
        match scope.as_str() {
            "admin" | "publish" | "token.manage" | "owner.manage" => {}
            _ => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "X07REG_SCOPE_INVALID",
                    format!("unsupported scope: {scope:?}"),
                )
            }
        }
    }
    scopes.sort();
    scopes.dedup();

    let is_admin = auth.scopes.iter().any(|s| s == "admin");
    if !is_admin {
        for scope in &scopes {
            if !auth.scopes.iter().any(|s| s == scope) {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "X07REG_FORBIDDEN",
                    format!("cannot grant scope: {scope}"),
                );
            }
        }
    }

    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("begin transaction: {err}"),
            )
        }
    };

    let (token_id, token) = {
        let mut rng = rand::rngs::OsRng;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            if attempt > 10 {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_TOKEN_GENERATION_FAILED",
                    "failed to allocate a unique token",
                );
            }
            let mut raw = [0u8; 32];
            rng.fill_bytes(&mut raw);
            let token = format!("x07t_{}", sha256_hex(&raw));
            let token_hash = sha256_hex(token.as_bytes());

            let inserted: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
                "INSERT INTO tokens(user_id, token_hash, label, scopes) VALUES ($1, $2, $3, $4) RETURNING id",
            )
            .bind(auth.user_id)
            .bind(&token_hash)
            .bind(&label)
            .bind(&scopes)
            .fetch_one(&mut *tx)
            .await;
            match inserted {
                Ok(id) => break (id, token),
                Err(sqlx::Error::Database(db_err))
                    if db_err.code().as_deref() == Some("23505") =>
                {
                    continue
                }
                Err(err) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "X07REG_DB",
                        format!("insert token: {err}"),
                    )
                }
            }
        }
    };

    if let Err(err) = sqlx::query(
        "INSERT INTO audit_events(actor_user_id, actor_token_id, action, details) VALUES ($1, $2, 'token_created', $3)",
    )
    .bind(auth.user_id)
    .bind(auth.token_id)
    .bind(serde_json::json!({ "label": &label, "scopes": &scopes }))
    .execute(&mut *tx)
    .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert audit: {err}"),
        );
    }

    if let Err(err) = tx.commit().await {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("commit: {err}"),
        );
    }

    ok_json(TokenCreateResponse {
        ok: true,
        token_id,
        token,
        scopes,
    })
}

#[derive(Debug, Serialize)]
struct SimpleOkResponse {
    ok: bool,
}

async fn token_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxPath(token_id): AxPath<Uuid>,
) -> Response {
    let auth = match require_token(&headers, state.as_ref(), &["token.manage"]).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let is_admin = auth.scopes.iter().any(|s| s == "admin");

    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("begin transaction: {err}"),
            )
        }
    };

    let updated = match sqlx::query(
        "UPDATE tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1 AND ($2 OR user_id = $3)",
    )
    .bind(token_id)
    .bind(is_admin)
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("revoke token: {err}"),
            )
        }
    };

    if updated.rows_affected() == 0 {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found");
    }

    if let Err(err) = sqlx::query(
        "INSERT INTO audit_events(actor_user_id, actor_token_id, action, details) VALUES ($1, $2, 'token_revoked', $3)",
    )
    .bind(auth.user_id)
    .bind(auth.token_id)
    .bind(serde_json::json!({ "token_id": token_id }))
    .execute(&mut *tx)
    .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert audit: {err}"),
        );
    }

    if let Err(err) = tx.commit().await {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("commit: {err}"),
        );
    }

    ok_json(SimpleOkResponse { ok: true })
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

#[derive(Debug, Deserialize, Serialize)]
struct IndexCatalogPackage {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct IndexCatalog {
    schema_version: String,
    packages: Vec<IndexCatalogPackage>,
}

async fn publish(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Body) -> Response {
    let auth = match require_token(&headers, state.as_ref(), &["publish"]).await {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };

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
    let (manifest, _manifest_bytes) = match read_package_manifest_from_tar(&bytes) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    if manifest.schema_version.trim() != "x07.package@0.1.0" {
        return json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_PKG_SCHEMA_VERSION",
            format!(
                "unsupported package schema_version: {:?}",
                manifest.schema_version
            ),
        );
    }
    if let Err(resp) = validate_pkg_name(&manifest.name) {
        return *resp;
    }
    if let Err(resp) = validate_version(&manifest.version) {
        return *resp;
    }

    let _publish_guard = state.publish_lock.lock().await;

    let pkg_name = &manifest.name;
    let pkg_version = &manifest.version;
    let index_rel = match index_relative_path(pkg_name) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let dl_key = format!("dl/{}/{}/download", pkg_name, pkg_version);
    let lock_id = advisory_lock_id(pkg_name);
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("begin transaction: {err}"),
            )
        }
    };
    if let Err(err) = sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_id)
        .execute(&mut *tx)
        .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("advisory lock: {err}"),
        );
    }

    #[derive(sqlx::FromRow)]
    struct PackageRow {
        id: Uuid,
        latest_version: Option<String>,
    }

    let existing: Option<PackageRow> = match sqlx::query_as(
        "SELECT id, latest_version FROM packages WHERE name = $1",
    )
    .bind(pkg_name)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select package: {err}"),
            )
        }
    };

    let is_admin = auth.scopes.iter().any(|s| s == "admin");

    let (package_id, current_latest) = if let Some(row) = existing {
        if !is_admin {
            let owner: Option<i32> = match sqlx::query_scalar(
                "SELECT 1 FROM package_owners WHERE package_id = $1 AND user_id = $2",
            )
            .bind(row.id)
            .bind(auth.user_id)
            .fetch_optional(&mut *tx)
            .await
            {
                Ok(v) => v,
                Err(err) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "X07REG_DB",
                        format!("check owner: {err}"),
                    )
                }
            };
            if owner.is_none() {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "X07REG_FORBIDDEN",
                    "not a package owner",
                );
            }
        }
        (row.id, row.latest_version)
    } else {
        let row: PackageRow = match sqlx::query_as(
            "INSERT INTO packages(name, created_by, latest_version) VALUES ($1, $2, NULL) RETURNING id, latest_version",
        )
        .bind(pkg_name)
        .bind(auth.user_id)
        .fetch_one(&mut *tx)
        .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("insert package: {err}"),
                )
            }
        };
        if let Err(err) = sqlx::query(
            "INSERT INTO package_owners(package_id, user_id) VALUES ($1, $2)",
        )
        .bind(row.id)
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("insert owner: {err}"),
            );
        }
        (row.id, row.latest_version)
    };

    let version_exists: Option<i32> = match sqlx::query_scalar(
        "SELECT 1 FROM package_versions WHERE package_id = $1 AND version = $2",
    )
    .bind(package_id)
    .bind(pkg_version)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("check version: {err}"),
            )
        }
    };
    if version_exists.is_some() {
        return json_error(
            StatusCode::CONFLICT,
            "X07REG_ALREADY_PUBLISHED",
            "package version already exists",
        );
    }

    match state.store.exists(&dl_key).await {
        Ok(true) => {
            return json_error(
                StatusCode::CONFLICT,
                "X07REG_ALREADY_PUBLISHED",
                "package version already exists",
            )
        }
        Ok(false) => {}
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_STORAGE",
                format!("check {dl_key:?}: {err}"),
            )
        }
    }

    let tar_bytes = bytes.to_vec();
    if let Err(err) = state
        .store
        .put(&dl_key, tar_bytes, Some("application/octet-stream"))
        .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_STORAGE",
            format!("write {dl_key:?}: {err}"),
        );
    }

    let manifest_json = match serde_json::to_value(&manifest) {
        Ok(v) => v,
        Err(err) => {
            let _ = state.store.delete(&dl_key).await;
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_INTERNAL",
                format!("serialize manifest: {err}"),
            );
        }
    };
    if let Err(err) = sqlx::query(
        "INSERT INTO package_versions(package_id, version, cksum, yanked, manifest, published_by) VALUES ($1, $2, $3, false, $4, $5)",
    )
    .bind(package_id)
    .bind(pkg_version)
    .bind(&cksum)
    .bind(manifest_json)
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await
    {
        let _ = state.store.delete(&dl_key).await;
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert version: {err}"),
        );
    }

    let should_update_latest = match current_latest {
        None => true,
        Some(ref cur) => match (Version::parse(cur), Version::parse(pkg_version)) {
            (Ok(cur), Ok(new)) => new > cur,
            (Err(_), Ok(_)) => true,
            _ => false,
        },
    };
    if should_update_latest {
        if let Err(err) = sqlx::query("UPDATE packages SET latest_version = $1 WHERE id = $2")
            .bind(pkg_version)
            .bind(package_id)
            .execute(&mut *tx)
            .await
        {
            let _ = state.store.delete(&dl_key).await;
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("update latest: {err}"),
            );
        }
    }

    if let Err(err) = sqlx::query(
        "INSERT INTO audit_events(actor_user_id, actor_token_id, action, package_name, package_version) VALUES ($1, $2, 'publish', $3, $4)",
    )
    .bind(auth.user_id)
    .bind(auth.token_id)
    .bind(pkg_name)
    .bind(pkg_version)
    .execute(&mut *tx)
    .await
    {
        let _ = state.store.delete(&dl_key).await;
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert audit: {err}"),
        );
    }

    if let Err(err) = tx.commit().await {
        let _ = state.store.delete(&dl_key).await;
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("commit: {err}"),
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

#[derive(Debug, Deserialize)]
struct SearchParams {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Serialize)]
struct SearchHit {
    name: String,
    latest_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct SearchResponse {
    ok: bool,
    q: String,
    limit: u32,
    offset: u32,
    total: i64,
    packages: Vec<SearchHit>,
}

async fn search(State(state): State<Arc<AppState>>, Query(params): Query<SearchParams>) -> Response {
    let q = params.q.trim().to_string();
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    #[derive(sqlx::FromRow)]
    struct Row {
        name: String,
        latest_version: Option<String>,
    }

    let (total, rows): (i64, Vec<Row>) = if q.is_empty() {
        let total: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM packages")
            .fetch_one(&state.db)
            .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("count packages: {err}"),
                )
            }
        };
        let rows: Vec<Row> = match sqlx::query_as(
            "SELECT name, latest_version FROM packages ORDER BY name ASC LIMIT $1 OFFSET $2",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&state.db)
        .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("select packages: {err}"),
                )
            }
        };
        (total, rows)
    } else {
        let like = format!("%{q}%");
        let total: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM packages WHERE name LIKE $1")
            .bind(&like)
            .fetch_one(&state.db)
            .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("count search: {err}"),
                )
            }
        };
        let rows: Vec<Row> = match sqlx::query_as(
            "SELECT name, latest_version FROM packages WHERE name LIKE $1 ORDER BY name ASC LIMIT $2 OFFSET $3",
        )
        .bind(&like)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&state.db)
        .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("select search: {err}"),
                )
            }
        };
        (total, rows)
    };

    ok_json(SearchResponse {
        ok: true,
        q,
        limit,
        offset,
        total,
        packages: rows
            .into_iter()
            .map(|r| SearchHit {
                name: r.name,
                latest_version: r.latest_version,
            })
            .collect(),
    })
}

#[derive(Debug, Serialize)]
struct PackageVersionInfo {
    version: String,
    cksum: String,
    yanked: bool,
    published_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct PackageDetailResponse {
    ok: bool,
    name: String,
    latest_version: Option<String>,
    owners: Vec<String>,
    versions: Vec<PackageVersionInfo>,
}

async fn package_detail(State(state): State<Arc<AppState>>, AxPath(name): AxPath<String>) -> Response {
    if let Err(resp) = validate_pkg_name(&name) {
        return *resp;
    }

    #[derive(sqlx::FromRow)]
    struct PackageRow {
        id: Uuid,
        latest_version: Option<String>,
    }

    let pkg: Option<PackageRow> = match sqlx::query_as(
        "SELECT id, latest_version FROM packages WHERE name = $1",
    )
    .bind(&name)
    .fetch_optional(&state.db)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select package: {err}"),
            )
        }
    };
    let Some(pkg) = pkg else {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found");
    };

    #[derive(sqlx::FromRow)]
    struct VersionRow {
        version: String,
        cksum: String,
        yanked: bool,
        published_at: DateTime<Utc>,
    }

    let mut versions: Vec<VersionRow> = match sqlx::query_as(
        "SELECT version, cksum, yanked, published_at FROM package_versions WHERE package_id = $1",
    )
    .bind(pkg.id)
    .fetch_all(&state.db)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select versions: {err}"),
            )
        }
    };

    let owners: Vec<String> = match sqlx::query_scalar(
        "SELECT u.handle FROM package_owners o JOIN users u ON u.id = o.user_id WHERE o.package_id = $1 ORDER BY u.handle ASC",
    )
    .bind(pkg.id)
    .fetch_all(&state.db)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select owners: {err}"),
            )
        }
    };

    versions.sort_by(|a, b| {
        let va = Version::parse(&a.version);
        let vb = Version::parse(&b.version);
        match (va, vb) {
            (Ok(va), Ok(vb)) => va.cmp(&vb),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => a.version.cmp(&b.version),
        }
    });

    ok_json(PackageDetailResponse {
        ok: true,
        name,
        latest_version: pkg.latest_version,
        owners,
        versions: versions
            .into_iter()
            .rev()
            .map(|v| PackageVersionInfo {
                version: v.version,
                cksum: v.cksum,
                yanked: v.yanked,
                published_at: v.published_at,
            })
            .collect(),
    })
}

#[derive(Debug, Serialize)]
struct OwnersResponse {
    ok: bool,
    name: String,
    owners: Vec<String>,
}

async fn package_owners_list(State(state): State<Arc<AppState>>, AxPath(name): AxPath<String>) -> Response {
    if let Err(resp) = validate_pkg_name(&name) {
        return *resp;
    }

    let pkg_id: Option<Uuid> = match sqlx::query_scalar("SELECT id FROM packages WHERE name = $1")
        .bind(&name)
        .fetch_optional(&state.db)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select package: {err}"),
            )
        }
    };
    let Some(pkg_id) = pkg_id else {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found");
    };

    let owners: Vec<String> = match sqlx::query_scalar(
        "SELECT u.handle FROM package_owners o JOIN users u ON u.id = o.user_id WHERE o.package_id = $1 ORDER BY u.handle ASC",
    )
    .bind(pkg_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select owners: {err}"),
            )
        }
    };

    ok_json(OwnersResponse {
        ok: true,
        name,
        owners,
    })
}

#[derive(Debug, Deserialize)]
struct OwnerChangeRequest {
    handle: String,
}

async fn package_owner_add(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxPath(name): AxPath<String>,
    Json(req): Json<OwnerChangeRequest>,
) -> Response {
    let auth = match require_token(&headers, state.as_ref(), &["owner.manage"]).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if let Err(resp) = validate_pkg_name(&name) {
        return *resp;
    }
    let handle = req.handle.trim().to_ascii_lowercase();
    if let Err(resp) = validate_pkg_name(&handle) {
        return *resp;
    }
    let is_admin = auth.scopes.iter().any(|s| s == "admin");

    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("begin transaction: {err}"),
            )
        }
    };
    let lock_id = advisory_lock_id(&name);
    if let Err(err) = sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_id)
        .execute(&mut *tx)
        .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("advisory lock: {err}"),
        );
    }

    let pkg_id: Option<Uuid> = match sqlx::query_scalar("SELECT id FROM packages WHERE name = $1")
        .bind(&name)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select package: {err}"),
            )
        }
    };
    let Some(pkg_id) = pkg_id else {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found");
    };

    if !is_admin {
        let owner: Option<i32> = match sqlx::query_scalar(
            "SELECT 1 FROM package_owners WHERE package_id = $1 AND user_id = $2",
        )
        .bind(pkg_id)
        .bind(auth.user_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("check owner: {err}"),
                )
            }
        };
        if owner.is_none() {
            return json_error(
                StatusCode::FORBIDDEN,
                "X07REG_FORBIDDEN",
                "not a package owner",
            );
        }
    }

    let new_owner_id: Option<Uuid> = match sqlx::query_scalar("SELECT id FROM users WHERE handle = $1")
        .bind(&handle)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select user: {err}"),
            )
        }
    };
    let Some(new_owner_id) = new_owner_id else {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "user not found");
    };

    if let Err(err) = sqlx::query(
        "INSERT INTO package_owners(package_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(pkg_id)
    .bind(new_owner_id)
    .execute(&mut *tx)
    .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert owner: {err}"),
        );
    }

    if let Err(err) = sqlx::query(
        "INSERT INTO audit_events(actor_user_id, actor_token_id, action, package_name, details) VALUES ($1, $2, 'owner_added', $3, $4)",
    )
    .bind(auth.user_id)
    .bind(auth.token_id)
    .bind(&name)
    .bind(serde_json::json!({ "handle": &handle }))
    .execute(&mut *tx)
    .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert audit: {err}"),
        );
    }

    if let Err(err) = tx.commit().await {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("commit: {err}"),
        );
    }

    ok_json(SimpleOkResponse { ok: true })
}

async fn package_owner_remove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxPath((name, handle)): AxPath<(String, String)>,
) -> Response {
    let auth = match require_token(&headers, state.as_ref(), &["owner.manage"]).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if let Err(resp) = validate_pkg_name(&name) {
        return *resp;
    }
    let handle = handle.trim().to_ascii_lowercase();
    if let Err(resp) = validate_pkg_name(&handle) {
        return *resp;
    }
    let is_admin = auth.scopes.iter().any(|s| s == "admin");

    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("begin transaction: {err}"),
            )
        }
    };
    let lock_id = advisory_lock_id(&name);
    if let Err(err) = sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_id)
        .execute(&mut *tx)
        .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("advisory lock: {err}"),
        );
    }

    let pkg_id: Option<Uuid> = match sqlx::query_scalar("SELECT id FROM packages WHERE name = $1")
        .bind(&name)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select package: {err}"),
            )
        }
    };
    let Some(pkg_id) = pkg_id else {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found");
    };

    if !is_admin {
        let owner: Option<i32> = match sqlx::query_scalar(
            "SELECT 1 FROM package_owners WHERE package_id = $1 AND user_id = $2",
        )
        .bind(pkg_id)
        .bind(auth.user_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("check owner: {err}"),
                )
            }
        };
        if owner.is_none() {
            return json_error(
                StatusCode::FORBIDDEN,
                "X07REG_FORBIDDEN",
                "not a package owner",
            );
        }
    }

    let owner_id: Option<Uuid> = match sqlx::query_scalar("SELECT id FROM users WHERE handle = $1")
        .bind(&handle)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select user: {err}"),
            )
        }
    };
    let Some(owner_id) = owner_id else {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "user not found");
    };

    let is_owner: Option<i32> = match sqlx::query_scalar(
        "SELECT 1 FROM package_owners WHERE package_id = $1 AND user_id = $2",
    )
    .bind(pkg_id)
    .bind(owner_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("check owner exists: {err}"),
            )
        }
    };
    if is_owner.is_none() {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "owner not found");
    }

    let owners_count: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM package_owners WHERE package_id = $1",
    )
    .bind(pkg_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("count owners: {err}"),
            )
        }
    };
    if owners_count <= 1 {
        return json_error(
            StatusCode::FORBIDDEN,
            "X07REG_FORBIDDEN",
            "cannot remove last owner",
        );
    }

    if let Err(err) = sqlx::query("DELETE FROM package_owners WHERE package_id = $1 AND user_id = $2")
        .bind(pkg_id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("delete owner: {err}"),
        );
    }

    if let Err(err) = sqlx::query(
        "INSERT INTO audit_events(actor_user_id, actor_token_id, action, package_name, details) VALUES ($1, $2, 'owner_removed', $3, $4)",
    )
    .bind(auth.user_id)
    .bind(auth.token_id)
    .bind(&name)
    .bind(serde_json::json!({ "handle": &handle }))
    .execute(&mut *tx)
    .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert audit: {err}"),
        );
    }

    if let Err(err) = tx.commit().await {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("commit: {err}"),
        );
    }

    ok_json(SimpleOkResponse { ok: true })
}

#[derive(Debug, Deserialize)]
struct YankRequest {
    yanked: bool,
}

#[derive(Debug, Serialize)]
struct YankResponse {
    ok: bool,
    name: String,
    version: String,
    yanked: bool,
}

async fn package_yank(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxPath((name, version)): AxPath<(String, String)>,
    Json(req): Json<YankRequest>,
) -> Response {
    let auth = match require_token(&headers, state.as_ref(), &["owner.manage"]).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if let Err(resp) = validate_pkg_name(&name) {
        return *resp;
    }
    if let Err(resp) = validate_version(&version) {
        return *resp;
    }
    let is_admin = auth.scopes.iter().any(|s| s == "admin");

    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("begin transaction: {err}"),
            )
        }
    };
    let lock_id = advisory_lock_id(&name);
    if let Err(err) = sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_id)
        .execute(&mut *tx)
        .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("advisory lock: {err}"),
        );
    }

    #[derive(sqlx::FromRow)]
    struct PackageRow {
        id: Uuid,
        latest_version: Option<String>,
    }

    let pkg: Option<PackageRow> = match sqlx::query_as(
        "SELECT id, latest_version FROM packages WHERE name = $1",
    )
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select package: {err}"),
            )
        }
    };
    let Some(pkg) = pkg else {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found");
    };

    if !is_admin {
        let owner: Option<i32> = match sqlx::query_scalar(
            "SELECT 1 FROM package_owners WHERE package_id = $1 AND user_id = $2",
        )
        .bind(pkg.id)
        .bind(auth.user_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(v) => v,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "X07REG_DB",
                    format!("check owner: {err}"),
                )
            }
        };
        if owner.is_none() {
            return json_error(
                StatusCode::FORBIDDEN,
                "X07REG_FORBIDDEN",
                "not a package owner",
            );
        }
    }

    let updated = match sqlx::query(
        "UPDATE package_versions SET yanked = $1 WHERE package_id = $2 AND version = $3",
    )
    .bind(req.yanked)
    .bind(pkg.id)
    .bind(&version)
    .execute(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("update yanked: {err}"),
            )
        }
    };
    if updated.rows_affected() == 0 {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found");
    }

    let action = if req.yanked { "yank" } else { "unyank" };
    if let Err(err) = sqlx::query(
        "INSERT INTO audit_events(actor_user_id, actor_token_id, action, package_name, package_version) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(auth.user_id)
    .bind(auth.token_id)
    .bind(action)
    .bind(&name)
    .bind(&version)
    .execute(&mut *tx)
    .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("insert audit: {err}"),
        );
    }

    let mut latest_version = pkg.latest_version;
    match (req.yanked, latest_version.as_deref()) {
        (true, Some(cur)) if cur == version => {
            let rows: Vec<String> = match sqlx::query_scalar(
                "SELECT version FROM package_versions WHERE package_id = $1 AND yanked = false",
            )
            .bind(pkg.id)
            .fetch_all(&mut *tx)
            .await
            {
                Ok(v) => v,
                Err(err) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "X07REG_DB",
                        format!("select versions: {err}"),
                    )
                }
            };

            let mut best: Option<(Version, String)> = None;
            for v in rows {
                let Ok(parsed) = Version::parse(&v) else {
                    continue;
                };
                match best {
                    None => best = Some((parsed, v)),
                    Some((ref cur, _)) if parsed > *cur => best = Some((parsed, v)),
                    _ => {}
                }
            }
            latest_version = best.map(|(_, v)| v);
        }
        (false, Some(cur)) => match (Version::parse(cur), Version::parse(&version)) {
            (Ok(cur), Ok(new)) if new > cur => latest_version = Some(version.clone()),
            (Err(_), Ok(_)) => latest_version = Some(version.clone()),
            _ => {}
        },
        (false, None) => latest_version = Some(version.clone()),
        _ => {}
    }

    if let Err(err) = sqlx::query("UPDATE packages SET latest_version = $1 WHERE id = $2")
        .bind(&latest_version)
        .bind(pkg.id)
        .execute(&mut *tx)
        .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("update latest: {err}"),
        );
    }

    if let Err(err) = tx.commit().await {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "X07REG_DB",
            format!("commit: {err}"),
        );
    }

    ok_json(YankResponse {
        ok: true,
        name,
        version,
        yanked: req.yanked,
    })
}

async fn download(
    State(state): State<Arc<AppState>>,
    AxPath((name, version)): AxPath<(String, String)>,
) -> Response {
    if let Err(resp) = validate_pkg_name(&name) {
        return *resp;
    }
    if let Err(resp) = validate_version(&version) {
        return *resp;
    }
    let key = format!("dl/{name}/{version}/download");
    let bytes = match state.store.get(&key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found"),
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_STORAGE",
                format!("read {key:?}: {err}"),
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
        return *resp;
    }
    if let Err(resp) = validate_version(&version) {
        return *resp;
    }

    #[derive(sqlx::FromRow)]
    struct MetaRow {
        manifest: serde_json::Value,
        cksum: String,
    }

    let row: Option<MetaRow> = match sqlx::query_as(
        r#"
        SELECT pv.manifest, pv.cksum
        FROM package_versions pv
        JOIN packages p ON p.id = pv.package_id
        WHERE p.name = $1 AND pv.version = $2
        "#,
    )
    .bind(&name)
    .bind(&version)
    .fetch_optional(&state.db)
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_DB",
                format!("select metadata: {err}"),
            )
        }
    };
    let Some(row) = row else {
        return json_error(StatusCode::NOT_FOUND, "X07REG_NOT_FOUND", "not found");
    };
    let pkg: PackageManifest = match serde_json::from_value(row.manifest) {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "X07REG_META_CORRUPT",
                format!("parse manifest json: {err}"),
            )
        }
    };

    ok_json(PackageMetadataResponse {
        ok: true,
        package: pkg,
        cksum: row.cksum,
    })
}

pub async fn app() -> Router {
    app_with_config(RegistryConfig::from_env()).await
}

pub async fn app_with_config(cfg: RegistryConfig) -> Router {
    let cors = cors_layer(&cfg);

    let store = match &cfg.storage {
        RegistryStorageConfig::Filesystem { data_dir } => Store::Fs(FsStore {
            root: data_dir.clone(),
        }),
        RegistryStorageConfig::S3(s3_cfg) => {
            let creds = aws_credential_types::Credentials::new(
                s3_cfg.access_key_id.clone(),
                s3_cfg.secret_access_key.clone(),
                None,
                None,
                "x07-registry",
            );
            let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_types::region::Region::new(s3_cfg.region.clone()))
                .credentials_provider(creds)
                .load()
                .await;

            let s3_config = aws_sdk_s3::config::Builder::from(&shared)
                .endpoint_url(s3_cfg.endpoint.trim())
                .force_path_style(s3_cfg.force_path_style)
                .build();
            Store::S3(S3Store {
                client: aws_sdk_s3::Client::from_conf(s3_config),
                bucket: s3_cfg.bucket.clone(),
                prefix: S3Store::normalize_prefix(&s3_cfg.prefix),
            })
        }
    };

    if !is_valid_db_schema_name(&cfg.database_schema) {
        panic!("invalid X07_REGISTRY_DATABASE_SCHEMA");
    }
    let schema = cfg.database_schema.clone();
    let db = PgPoolOptions::new()
        .max_connections(10)
        .after_connect(move |conn, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                let stmt = format!("SET search_path TO \"{schema}\", public");
                sqlx::query(&stmt).execute(conn).await?;
                Ok(())
            })
        })
        .connect(&cfg.database_url)
        .await
        .expect("connect postgres");

    let create_schema_stmt = format!("CREATE SCHEMA IF NOT EXISTS \"{}\"", cfg.database_schema);
    sqlx::query(&create_schema_stmt)
        .execute(&db)
        .await
        .expect("create postgres schema");
    sqlx::migrate!().run(&db).await.expect("migrate postgres");

    let state = Arc::new(AppState {
        cfg,
        store,
        db,
        publish_lock: Mutex::new(()),
    });
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/index/config.json", get(index_config))
        .route("/index/{*path}", get(index_file))
        .route("/v1/admin/bootstrap", post(admin_bootstrap))
        .route("/v1/auth/token", post(token))
        .route("/v1/account", get(account))
        .route("/v1/search", get(search))
        .route("/v1/tokens", get(tokens_list).post(token_create))
        .route("/v1/tokens/{token_id}/revoke", post(token_revoke))
        .route("/v1/packages/publish", post(publish))
        .route("/v1/packages/{name}/{version}/download", get(download))
        .route(
            "/v1/packages/{name}/{version}/metadata",
            get(package_metadata),
        )
        .route("/v1/packages/{name}", get(package_detail))
        .route(
            "/v1/packages/{name}/owners",
            get(package_owners_list).post(package_owner_add),
        )
        .route(
            "/v1/packages/{name}/owners/{handle}",
            delete(package_owner_remove),
        )
        .route("/v1/packages/{name}/{version}/yank", post(package_yank))
        .with_state(state);
    match cors {
        Some(cors) => app.layer(cors),
        None => app,
    }
}

fn cors_layer(cfg: &RegistryConfig) -> Option<CorsLayer> {
    if cfg.cors_origins.is_empty() {
        return None;
    }
    if cfg.cors_origins.iter().any(|o| o == "*") {
        return Some(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    Method::GET,
                    Method::HEAD,
                    Method::OPTIONS,
                    Method::POST,
                    Method::DELETE,
                ])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE]),
        );
    }

    let mut origins: Vec<HeaderValue> = Vec::new();
    for origin in &cfg.cors_origins {
        match HeaderValue::from_str(origin) {
            Ok(v) => origins.push(v),
            Err(_) => {
                return None;
            }
        }
    }

    Some(
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                Method::GET,
                Method::HEAD,
                Method::OPTIONS,
                Method::POST,
                Method::DELETE,
            ])
            .allow_headers([AUTHORIZATION, CONTENT_TYPE]),
    )
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

fn advisory_lock_id(package_name: &str) -> i64 {
    let mut h = Sha256::new();
    h.update(b"x07-registry:package:");
    h.update(package_name.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(bytes)
}

fn read_package_manifest_from_tar(tar_bytes: &[u8]) -> ApiResult<(PackageManifest, Vec<u8>)> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    for entry in archive.entries().map_err(|e| {
        boxed_json_error(
            StatusCode::BAD_REQUEST,
            "X07REG_BAD_ARCHIVE",
            format!("read tar entries: {e}"),
        )
    })? {
        let mut entry = entry.map_err(|e| {
            boxed_json_error(
                StatusCode::BAD_REQUEST,
                "X07REG_BAD_ARCHIVE",
                format!("read tar entry: {e}"),
            )
        })?;
        let path = entry.path().map_err(|e| {
            boxed_json_error(
                StatusCode::BAD_REQUEST,
                "X07REG_BAD_ARCHIVE",
                format!("read tar entry path: {e}"),
            )
        })?;
        if path.as_ref() == Path::new("x07-package.json") {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).map_err(|e| {
                boxed_json_error(StatusCode::BAD_REQUEST, "X07REG_BAD_ARCHIVE", e.to_string())
            })?;
            let pkg: PackageManifest = serde_json::from_slice(&bytes).map_err(|e| {
                boxed_json_error(
                    StatusCode::BAD_REQUEST,
                    "X07REG_BAD_MANIFEST",
                    format!("parse x07-package.json: {e}"),
                )
            })?;
            return Ok((pkg, bytes));
        }
    }
    Err(boxed_json_error(
        StatusCode::BAD_REQUEST,
        "X07REG_BAD_ARCHIVE",
        "missing x07-package.json",
    ))
}

fn index_relative_path(name: &str) -> ApiResult<String> {
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
