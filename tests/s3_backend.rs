use aws_sdk_s3::error::ProvideErrorMetadata;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rand::RngCore;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashSet;
use tower::ServiceExt;
use uuid::Uuid;

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;

    let mut h = sha2::Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

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

async fn connect_test_db(database_url: &str, schema: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .after_connect({
            let schema = schema.to_string();
            move |conn, _meta| {
                let schema = schema.clone();
                Box::pin(async move {
                    let stmt = format!("SET search_path TO \"{schema}\", public");
                    sqlx::query(&stmt).execute(conn).await?;
                    Ok(())
                })
            }
        })
        .connect(database_url)
        .await
        .expect("connect test db")
}

async fn create_user_with_token(database_url: &str, schema: &str, handle: &str) -> String {
    let pool = connect_test_db(database_url, schema).await;

    let handle = handle.trim().to_ascii_lowercase();

    let github_user_id: i64 = {
        let mut raw = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        i64::from_le_bytes(raw).abs().max(1)
    };

    let user_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users(handle, created_via, github_user_id, github_login, github_email, github_email_verified, github_email_primary)
        VALUES ($1, 'github', $2, $3, $4, true, true)
        ON CONFLICT(handle) DO UPDATE
            SET created_via='github',
                github_user_id=EXCLUDED.github_user_id,
                github_login=EXCLUDED.github_login,
                github_email=EXCLUDED.github_email,
                github_email_verified=true,
                github_email_primary=true
        RETURNING id
        "#,
    )
    .bind(&handle)
    .bind(github_user_id)
    .bind(&handle)
    .bind(format!("{handle}@example.com"))
    .fetch_one(&pool)
    .await
    .expect("insert user");

    let token = {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        format!("x07t_{}", sha256_hex(&raw))
    };
    let token_hash = sha256_hex(token.as_bytes());
    let scopes = vec!["publish".to_string()];

    sqlx::query("INSERT INTO tokens(user_id, token_hash, label, scopes) VALUES ($1, $2, '', $3)")
        .bind(user_id)
        .bind(token_hash)
        .bind(scopes)
        .execute(&pool)
        .await
        .expect("insert token");

    token
}

fn base_config(
    database_url: String,
    database_schema: String,
    storage: x07_registry::RegistryStorageConfig,
) -> x07_registry::RegistryConfig {
    x07_registry::RegistryConfig {
        public_base: "http://127.0.0.1:8080".to_string(),
        web_base: "http://127.0.0.1:3000".to_string(),
        database_url,
        database_schema,
        cors_origins: Vec::new(),
        storage,
        verified_namespaces: Vec::new(),
        github_oauth: None,
        admin_github_user_ids: HashSet::new(),
        session_cookie_domain: None,
        session_cookie_secure: false,
        session_ttl_seconds: 60 * 60,
        oauth_state_ttl_seconds: 600,
        require_verified_email_for_publish: true,
    }
}

fn make_tar_with_package(name: &str, version: &str) -> Vec<u8> {
    let manifest = serde_json::json!({
        "schema_version": "x07.package@0.1.0",
        "name": name,
        "description": "Test package used by x07-registry S3 integration tests.",
        "docs": "This package exists for x07-registry tests.\n\nUsage:\n- x07 pkg add <name>@<version>\n",
        "version": version,
        "module_root": "modules",
        "modules": ["hello.util"],
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("encode manifest");

    let module_bytes = br#"{"decls":[{"kind":"export","names":["hello.util.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"hello.util.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"hello.util","schema_version":"x07.x07ast@0.2.0"}"#.to_vec();

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

fn env_var(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

async fn ensure_bucket(cfg: &x07_registry::RegistryS3Config) {
    let creds = aws_credential_types::Credentials::new(
        cfg.access_key_id.clone(),
        cfg.secret_access_key.clone(),
        None,
        None,
        "x07-registry-test",
    );
    let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_types::region::Region::new(cfg.region.clone()))
        .credentials_provider(creds)
        .load()
        .await;

    let s3_config = aws_sdk_s3::config::Builder::from(&shared)
        .endpoint_url(cfg.endpoint.trim())
        .force_path_style(cfg.force_path_style)
        .build();
    let client = aws_sdk_s3::Client::from_conf(s3_config);

    for attempt in 0..60 {
        match client.create_bucket().bucket(&cfg.bucket).send().await {
            Ok(_) => return,
            Err(err) => {
                if let aws_sdk_s3::error::SdkError::ServiceError(service_err) = &err {
                    if let Some(code) = service_err.err().code() {
                        if code == "BucketAlreadyOwnedByYou" || code == "BucketAlreadyExists" {
                            return;
                        }
                    }
                }

                if attempt == 59 {
                    panic!("create bucket failed: {err}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
    }
}

#[tokio::test]
async fn s3_backend_publish_creates_index_and_download() {
    if std::env::var("X07_REGISTRY_TEST_S3").ok().as_deref() != Some("1") {
        return;
    }

    let bucket = env_var("X07_REGISTRY_TEST_S3_BUCKET", "x07-registry-test");
    let region = env_var("X07_REGISTRY_TEST_S3_REGION", "us-east-1");
    let endpoint = env_var("X07_REGISTRY_TEST_S3_ENDPOINT", "http://127.0.0.1:9000");
    let force_path_style =
        env_var("X07_REGISTRY_TEST_S3_FORCE_PATH_STYLE", "true").trim() == "true";
    let access_key_id = env_var("X07_REGISTRY_TEST_S3_ACCESS_KEY_ID", "minio");
    let secret_access_key = env_var("X07_REGISTRY_TEST_S3_SECRET_ACCESS_KEY", "minio123");

    let tmp = tempfile::tempdir().expect("tempdir");
    let prefix = tmp
        .path()
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let s3_cfg = x07_registry::RegistryS3Config {
        bucket,
        region,
        endpoint,
        prefix,
        force_path_style,
        access_key_id,
        secret_access_key,
    };
    ensure_bucket(&s3_cfg).await;

    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::S3(s3_cfg),
    ))
    .await;

    let token = create_user_with_token(&database_url, &database_schema, "tester").await;

    let tar = make_tar_with_package("hello", "0.1.0");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    let index_path = json["index_path"].as_str().expect("index_path str");
    let cksum = json["cksum"].as_str().expect("cksum str");
    assert_eq!(json["name"], Value::String("hello".to_string()));
    assert_eq!(json["version"], Value::String("0.1.0".to_string()));
    assert_eq!(cksum.len(), 64);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(index_path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let index_body = resp.into_body().collect().await.unwrap().to_bytes();
    let index_text = String::from_utf8(index_body.to_vec()).expect("index utf-8");
    assert!(index_text.contains("\"name\":\"hello\""));
    assert!(index_text.contains("\"version\":\"0.1.0\""));
    assert!(index_text.contains(cksum));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index/catalog.json")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(
        json["schema_version"],
        Value::String("x07.index-catalog@0.1.0".to_string())
    );
    assert_eq!(json["packages"].as_array().unwrap().len(), 1);
    assert_eq!(
        json["packages"][0]["name"],
        Value::String("hello".to_string())
    );
    assert_eq!(
        json["packages"][0]["latest"],
        Value::String("0.1.0".to_string())
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packages/hello/0.1.0/download")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let got_tar = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(got_tar.to_vec(), tar);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packages/hello/0.1.0/metadata")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["cksum"], Value::String(cksum.to_string()));
    assert_eq!(json["package"]["name"], Value::String("hello".to_string()));
}
