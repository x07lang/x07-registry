use axum::http::header::{LOCATION, SET_COOKIE};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashSet;
use tower::ServiceExt;
use uuid::Uuid;

async fn read_body_json(body: axum::body::Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    serde_json::from_slice(&bytes).expect("parse json body")
}

async fn create_test_schema() -> (String, String) {
    let database_url = std::env::var("X07_REGISTRY_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://x07:x07@127.0.0.1:55432/x07_registry".to_string());
    let schema = format!("test_{}", Uuid::new_v4().simple());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&database_url)
        .await
        .expect("connect postgres");
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&pool)
        .await
        .expect("create schema");

    (database_url, schema)
}

fn make_tar_with_package(name: &str, version: &str) -> Vec<u8> {
    let manifest = serde_json::json!({
        "schema_version": "x07.package@0.1.0",
        "name": name,
        "description": "Test package used by x07-registry OAuth integration tests.",
        "docs": "This package exists for x07-registry tests.\n\nUsage:\n- x07 pkg add <name>@<version>\n",
        "version": version,
        "module_root": "modules",
        "modules": ["hello.util"],
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("encode manifest");

    let module_bytes = br#"{"schema_version":"x07.x07ast@0.3.0","kind":"module","module_id":"hello.util","imports":[],"decls":[]}"#.to_vec();

    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        builder.mode(tar::HeaderMode::Deterministic);

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "x07-package.json",
                std::io::Cursor::new(&manifest_bytes),
            )
            .expect("append manifest");

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(module_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "modules/hello/util.x07.json",
                std::io::Cursor::new(&module_bytes),
            )
            .expect("append module");

        builder.finish().expect("finish tar");
    }
    buf
}

async fn start_github_stub() -> String {
    use axum::routing::{get, post};
    use axum::Json;

    async fn access_token() -> Json<Value> {
        Json(serde_json::json!({
            "access_token": "stub_access_token",
            "token_type": "bearer",
            "scope": "read:user user:email"
        }))
    }

    async fn user() -> Json<Value> {
        Json(serde_json::json!({
            "id": 424242,
            "login": "alice",
            "avatar_url": "https://example.com/avatar.png",
            "html_url": "https://github.com/alice"
        }))
    }

    async fn emails() -> Json<Value> {
        Json(serde_json::json!([
            {"email":"alice@example.com","primary":true,"verified":true}
        ]))
    }

    let app = axum::Router::new()
        .route("/login/oauth/access_token", post(access_token))
        .route("/user", get(user))
        .route("/user/emails", get(emails));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let addr = listener.local_addr().expect("stub local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve stub");
    });
    format!("http://{}", addr)
}

fn extract_cookie_value(set_cookie: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let rest = set_cookie.strip_prefix(&prefix)?;
    let value = rest.split(';').next()?.trim();
    (!value.is_empty()).then_some(value.to_string())
}

#[tokio::test]
async fn github_oauth_onboarding_can_create_token_and_publish() {
    let github_base = start_github_stub().await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;

    let app = x07_registry::app_with_config(x07_registry::RegistryConfig {
        public_base: "http://127.0.0.1:8080".to_string(),
        web_base: "http://localhost:3000".to_string(),
        database_url: database_url.clone(),
        database_schema: database_schema.clone(),
        cors_origins: vec!["http://localhost:3000".to_string()],
        storage: x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        verified_namespaces: Vec::new(),
        github_oauth: Some(x07_registry::GithubOAuthConfig {
            client_id: "stub_client_id".to_string(),
            client_secret: "stub_client_secret".to_string(),
            authorize_base: github_base.clone(),
            api_base: github_base.clone(),
        }),
        admin_github_user_ids: HashSet::new(),
        session_cookie_domain: None,
        session_cookie_secure: false,
        session_ttl_seconds: 60 * 60,
        oauth_state_ttl_seconds: 600,
        require_verified_email_for_publish: true,
    })
    .await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/github/start?next=/settings/tokens")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get(LOCATION)
        .expect("location")
        .to_str()
        .expect("location str");
    let state = {
        let url = reqwest::Url::parse(location).expect("authorize url");
        url.query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("state")
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/auth/github/callback?code=stub_code&state={state}"
                ))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers().get(LOCATION).unwrap(),
        "http://localhost:3000/settings/tokens"
    );
    let set_cookie = resp
        .headers()
        .get(SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .expect("set-cookie str");
    let session_cookie =
        extract_cookie_value(set_cookie, "x07_session").expect("x07_session cookie value");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/session")
                .header("Cookie", format!("x07_session={session_cookie}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["authenticated"], Value::Bool(true));
    assert_eq!(json["user"]["handle"], Value::String("alice".to_string()));
    assert_eq!(json["user"]["email_verified"], Value::Bool(true));
    let csrf_token = json["csrf_token"]
        .as_str()
        .expect("csrf_token str")
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tokens")
                .header("Cookie", format!("x07_session={session_cookie}"))
                .header("Origin", "http://localhost:3000")
                .header("X-X07-CSRF", csrf_token.as_str())
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"label":"test","scopes":["publish"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    let publish_token = json["token"].as_str().expect("token str").to_string();

    let tar = make_tar_with_package("hello", "0.1.0");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {publish_token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
