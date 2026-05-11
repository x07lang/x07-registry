use axum::http::header::{CACHE_CONTROL, ETAG, IF_NONE_MATCH, LOCATION};
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use rand::TryRngCore;
use serde_json::Value;
use std::collections::HashSet;
use tower::ServiceExt;
use uuid::Uuid;

mod support;

use support::{connect_test_db, create_test_schema};

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

async fn create_user_with_token(
    database_url: &str,
    schema: &str,
    handle: &str,
    scopes: &[&str],
) -> String {
    let pool = connect_test_db(database_url, schema).await;

    let handle = handle.trim().to_ascii_lowercase();

    let github_user_id: i64 = {
        let mut raw = [0u8; 8];
        rand::rngs::OsRng.try_fill_bytes(&mut raw).expect("os rng");
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
        rand::rngs::OsRng.try_fill_bytes(&mut raw).expect("os rng");
        format!("x07t_{}", sha256_hex(&raw))
    };
    let token_hash = sha256_hex(token.as_bytes());
    let scopes = scopes
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    sqlx::query("INSERT INTO tokens(user_id, token_hash, label, scopes) VALUES ($1, $2, '', $3)")
        .bind(user_id)
        .bind(token_hash)
        .bind(scopes)
        .execute(&pool)
        .await
        .expect("insert token");

    token
}

async fn create_session_for_user(
    database_url: &str,
    schema: &str,
    handle: &str,
) -> (String, String) {
    let pool = connect_test_db(database_url, schema).await;
    let handle = handle.trim().to_ascii_lowercase();

    let user_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE handle = $1")
        .bind(&handle)
        .fetch_one(&pool)
        .await
        .expect("select user");

    let session_token = {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut raw).expect("os rng");
        format!("x07s_{}", sha256_hex(&raw))
    };
    let session_token_hash = sha256_hex(session_token.as_bytes());
    let csrf_token = {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut raw).expect("os rng");
        format!("x07c_{}", sha256_hex(&raw))
    };
    let expires_at = Utc::now() + ChronoDuration::hours(1);

    sqlx::query(
        "INSERT INTO web_sessions(user_id, session_token_hash, csrf_token, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(session_token_hash)
    .bind(&csrf_token)
    .bind(expires_at)
    .execute(&pool)
    .await
    .expect("insert session");

    (session_token, csrf_token)
}

fn base_config(
    database_url: String,
    database_schema: String,
    storage: x07_registry::RegistryStorageConfig,
    cors_origins: Vec<String>,
) -> x07_registry::RegistryConfig {
    x07_registry::RegistryConfig {
        public_base: "http://127.0.0.1:8080".to_string(),
        web_base: "http://127.0.0.1:3000".to_string(),
        database_url,
        database_schema,
        cors_origins,
        storage,
        verified_namespaces: Vec::new(),
        github_oauth: None,
        admin_github_user_ids: HashSet::new(),
        scale_evidence_allowed_hosts: vec!["example.com".to_string()],
        scale_evidence_allowed_s3_buckets: Vec::new(),
        session_cookie_domain: None,
        session_cookie_secure: false,
        session_ttl_seconds: 60 * 60,
        oauth_state_ttl_seconds: 600,
        require_verified_email_for_publish: true,
        pkg_signing: None,
    }
}

fn make_tar_with_package(name: &str, version: &str) -> Vec<u8> {
    let module_bytes = br#"{"decls":[{"kind":"export","names":["hello.util.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"hello.util.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"hello.util","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();
    make_tar_with_package_with_module(name, version, module_bytes)
}

fn make_tar_with_package_with_module(name: &str, version: &str, module_bytes: Vec<u8>) -> Vec<u8> {
    make_tar_with_package_with_modules(name, version, None, vec![("hello.util", module_bytes)])
}

fn make_tar_with_manifest_and_modules(manifest: Value, modules: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("encode manifest");

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

        for (module_id, module_bytes) in modules {
            let rel = format!("modules/{}.x07.json", module_id.replace('.', "/"));
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(module_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            builder
                .append_data(&mut header, rel, std::io::Cursor::new(&module_bytes))
                .expect("append module");
        }

        builder.finish().expect("finish tar");
    }
    buf
}

fn make_tar_with_package_with_modules(
    name: &str,
    version: &str,
    meta: Option<Value>,
    modules: Vec<(&str, Vec<u8>)>,
) -> Vec<u8> {
    let module_ids: Vec<&str> = modules.iter().map(|(id, _)| *id).collect();
    let mut meta_obj = meta
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    meta_obj
        .entry("x07c_compat".to_string())
        .or_insert_with(|| Value::String(">=0.1.111 <0.3.0".to_string()));
    let mut manifest = serde_json::json!({
        "schema_version": "x07.package@0.1.0",
        "name": name,
        "description": "Test package used by x07-registry integration tests.",
        "license": "MIT OR Apache-2.0",
        "docs": "This package exists for x07-registry tests.\n\nUsage:\n- x07 pkg add <name>@<version>\n",
        "version": version,
        "module_root": "modules",
        "modules": module_ids,
    });
    manifest["meta"] = Value::Object(meta_obj);

    make_tar_with_manifest_and_modules(manifest, modules)
}

#[tokio::test]
async fn healthz_is_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url,
        database_schema,
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn scale_metadata_is_persisted_and_filterable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let module = br#"{"decls":[{"kind":"export","names":["svc.runtime.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"svc.runtime.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"svc.runtime","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();
    let tar = make_tar_with_package_with_modules(
        "x07-workload-pack-demo",
        "0.1.0",
        Some(serde_json::json!({
            "scale_classes_supported": ["replicated-http", "partitioned-consumer"],
            "scale_tested": true,
            "scale_test_evidence_ref": "https://example.com/evidence.json",
        })),
        vec![("svc.runtime", module)],
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let metadata = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/packages/x07-workload-pack-demo/0.1.0/metadata")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    assert_eq!(metadata["scale_tested"], Value::Bool(true));
    assert_eq!(
        metadata["scale_test_evidence_ref"],
        Value::String("https://example.com/evidence.json".to_string())
    );
    assert_eq!(
        metadata["scale_classes_supported"],
        serde_json::json!(["partitioned-consumer", "replicated-http"])
    );

    let search = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/search?scale_tested=true&q=workload")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    assert_eq!(search["total"].as_i64(), Some(1));
    assert_eq!(
        search["packages"][0]["name"],
        Value::String("x07-workload-pack-demo".to_string())
    );
}

#[tokio::test]
async fn scale_evidence_endpoint_enforces_allowlist_and_persists() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let module = br#"{"decls":[{"kind":"export","names":["svc.runtime.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"svc.runtime.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"svc.runtime","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();
    let tar = make_tar_with_package_with_modules(
        "x07-workload-pack-evidence",
        "0.1.0",
        Some(serde_json::json!({
            "scale_classes_supported": ["replicated-http"],
        })),
        vec![("svc.runtime", module)],
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packs/x07-workload-pack-evidence/versions/0.1.0/scale-evidence")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"evidence_ref":"https://evil.com/evidence.json"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packs/x07-workload-pack-evidence/versions/0.1.0/scale-evidence")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"evidence_ref":"https://example.com/evidence.json"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["scale_tested"], Value::Bool(true));
    assert_eq!(
        json["scale_test_evidence_ref"],
        Value::String("https://example.com/evidence.json".to_string())
    );

    let metadata = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/packages/x07-workload-pack-evidence/0.1.0/metadata")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    assert_eq!(metadata["scale_tested"], Value::Bool(true));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packs/x07-workload-pack-evidence/versions/0.1.0/scale-evidence")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"evidence_ref":"https://example.com/evidence.json"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packs/x07-workload-pack-evidence/versions/0.1.0/scale-evidence")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"evidence_ref":"https://example.com/other.json"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn index_config_is_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url,
        database_schema,
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/index/config.json")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["auth-required"], Value::Bool(false));
    assert_eq!(json["sparse"], Value::Bool(true));
    assert!(json["dl"].as_str().unwrap().ends_with("/v1/packages/"));
    assert!(json["api"].as_str().unwrap().ends_with("/v1/"));
}

#[tokio::test]
async fn index_signing_exposes_public_key_and_entry_signatures_verify() {
    use base64::Engine as _;
    use ed25519_dalek::Verifier as _;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;

    let mut cfg = base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    );
    cfg.pkg_signing = Some(x07_registry::RegistryPkgSigningConfig {
        key_id: "test-ed25519".to_string(),
        ed25519_seed: [7u8; 32],
    });
    let app = x07_registry::app_with_config(cfg).await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let cfg_json = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/index/config.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    assert_eq!(
        cfg_json["signing"]["kind"],
        Value::String("ed25519".to_string())
    );
    let key = &cfg_json["signing"]["public_keys"][0];
    assert_eq!(key["id"], Value::String("test-ed25519".to_string()));
    let pub_b64 = key["ed25519_pub"].as_str().expect("ed25519_pub");
    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(pub_b64)
        .expect("base64 decode ed25519_pub");
    let pub_bytes: [u8; 32] = pub_bytes.try_into().expect("ed25519_pub length");
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes).expect("verifying key");

    let tar = make_tar_with_package("hello", "0.1.0");
    let cksum = sha256_hex(&tar);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["cksum"], Value::String(cksum.clone()));
    let index_path = json["index_path"].as_str().expect("index_path str");

    let index_json: Value = {
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
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).expect("index utf-8");
        let line = text
            .lines()
            .find(|l| !l.trim().is_empty())
            .expect("ndjson line");
        serde_json::from_str(line).expect("parse ndjson line")
    };

    let sig_b64 = index_json["signature"]["ed25519_sig"]
        .as_str()
        .expect("ed25519_sig");
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .expect("base64 decode ed25519_sig");
    let sig_bytes: [u8; 64] = sig_bytes.try_into().expect("ed25519_sig length");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let msg = format!("x07.pkg.sig.v1\nname=hello\nversion=0.1.0\nsha256={cksum}\n");
    vk.verify(msg.as_bytes(), &sig).expect("verify signature");
}

#[tokio::test]
async fn index_signing_backfill_restores_missing_entry_signatures() {
    use base64::Engine as _;
    use ed25519_dalek::Verifier as _;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;

    let signing = x07_registry::RegistryPkgSigningConfig {
        key_id: "test-ed25519".to_string(),
        ed25519_seed: [7u8; 32],
    };
    let mut cfg = base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    );
    cfg.pkg_signing = Some(signing.clone());
    let app = x07_registry::app_with_config(cfg).await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let cfg_json = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/index/config.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    let pub_b64 = cfg_json["signing"]["public_keys"][0]["ed25519_pub"]
        .as_str()
        .expect("ed25519_pub");
    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(pub_b64)
        .expect("base64 decode ed25519_pub");
    let pub_bytes: [u8; 32] = pub_bytes.try_into().expect("ed25519_pub length");
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes).expect("verifying key");

    let tar = make_tar_with_package("hello", "0.1.0");
    let cksum = sha256_hex(&tar);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    let index_path = json["index_path"]
        .as_str()
        .expect("index_path str")
        .to_string();

    let pool = connect_test_db(&database_url, &database_schema).await;
    let cleared = sqlx::query(
        r#"
        UPDATE package_versions pv
        SET signature_kind = NULL,
            signature_key_id = NULL,
            signature_bytes = NULL
        FROM packages p
        WHERE p.id = pv.package_id AND p.name = $1 AND pv.version = $2
        "#,
    )
    .bind("hello")
    .bind("0.1.0")
    .execute(&pool)
    .await
    .expect("clear signature");
    assert_eq!(cleared.rows_affected(), 1);

    let index_json: Value = {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&index_path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).expect("index utf-8");
        let line = text
            .lines()
            .find(|l| !l.trim().is_empty())
            .expect("ndjson line");
        serde_json::from_str(line).expect("parse ndjson line")
    };
    assert!(
        index_json.get("signature").is_none(),
        "expected signature to be absent before backfill, got: {index_json}"
    );

    let report = x07_registry::backfill_pkg_signatures(&pool, &signing, false)
        .await
        .expect("backfill signatures");
    assert_eq!(report.total_versions, 1);
    assert_eq!(report.unsigned_before, 1);
    assert_eq!(report.unsigned_after, 0);
    assert_eq!(report.backfilled, 1);
    assert_eq!(report.dry_run, false);

    let index_json: Value = {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&index_path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).expect("index utf-8");
        let line = text
            .lines()
            .find(|l| !l.trim().is_empty())
            .expect("ndjson line");
        serde_json::from_str(line).expect("parse ndjson line")
    };

    let sig_b64 = index_json["signature"]["ed25519_sig"]
        .as_str()
        .expect("ed25519_sig");
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .expect("base64 decode ed25519_sig");
    let sig_bytes: [u8; 64] = sig_bytes.try_into().expect("ed25519_sig length");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let msg = format!("x07.pkg.sig.v1\nname=hello\nversion=0.1.0\nsha256={cksum}\n");
    vk.verify(msg.as_bytes(), &sig).expect("verify signature");
}

#[tokio::test]
async fn index_root_redirects_to_catalog() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url,
        database_schema,
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(resp.headers().get(LOCATION).unwrap(), "/index/");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/index/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(resp.headers().get(LOCATION).unwrap(), "/index/catalog.json");
}

#[tokio::test]
async fn index_config_auth_required_is_false_even_when_publish_requires_token() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url,
        database_schema,
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/index/config.json")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["auth-required"], Value::Bool(false));
    assert_eq!(json["sparse"], Value::Bool(true));
}

#[tokio::test]
async fn cors_allows_configured_origin_for_get_requests() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url,
        database_schema,
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        vec!["https://x07.io".to_string()],
    ))
    .await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("Origin", "https://x07.io")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "https://x07.io"
    );
}

#[tokio::test]
async fn publish_creates_index_and_download() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "webodik", &["publish"]).await;

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
    assert_eq!(
        resp.headers()
            .get(CACHE_CONTROL)
            .expect("cache-control")
            .to_str()
            .expect("cache-control str"),
        "public, max-age=300"
    );
    let index_etag = resp
        .headers()
        .get(ETAG)
        .expect("etag")
        .to_str()
        .expect("etag str")
        .to_string();
    let index_body = resp.into_body().collect().await.unwrap().to_bytes();
    let index_text = String::from_utf8(index_body.to_vec()).expect("index utf-8");
    assert!(index_text.contains("\"name\":\"hello\""));
    assert!(index_text.contains("\"version\":\"0.1.0\""));
    assert!(index_text.contains(cksum));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(index_path)
                .header(IF_NONE_MATCH, index_etag.as_str())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

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
    assert_eq!(
        resp.headers()
            .get(CACHE_CONTROL)
            .expect("cache-control")
            .to_str()
            .expect("cache-control str"),
        "public, max-age=300"
    );
    let catalog_etag = resp
        .headers()
        .get(ETAG)
        .expect("etag")
        .to_str()
        .expect("etag str")
        .to_string();
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
    assert_eq!(json["packages"][0]["is_official"], Value::Bool(true));
    assert_eq!(
        json["packages"][0]["latest"],
        Value::String("0.1.0".to_string())
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index/catalog.json")
                .header(IF_NONE_MATCH, catalog_etag.as_str())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

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
    assert_eq!(
        resp.headers()
            .get(CACHE_CONTROL)
            .expect("cache-control")
            .to_str()
            .expect("cache-control str"),
        "public, max-age=3600"
    );
    assert_eq!(
        resp.headers()
            .get(ETAG)
            .expect("etag")
            .to_str()
            .expect("etag str"),
        format!("\"{cksum}\"")
    );
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["cksum"], Value::String(cksum.to_string()));
    assert_eq!(json["package"]["name"], Value::String("hello".to_string()));
    assert_eq!(json["is_official"], Value::Bool(true));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packages/hello")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["name"], Value::String("hello".to_string()));
    assert_eq!(json["is_official"], Value::Bool(true));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packages/hello/owners")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["name"], Value::String("hello".to_string()));
    assert_eq!(json["is_official"], Value::Bool(true));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=hel")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(
        json["packages"][0]["name"],
        Value::String("hello".to_string())
    );
    assert_eq!(json["packages"][0]["is_official"], Value::Bool(true));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packages/hello/0.1.0/metadata")
                .header(IF_NONE_MATCH, format!("\"{cksum}\""))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn publish_accepts_mixed_worlds_packages() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let pure_module = br#"{"decls":[{"kind":"export","names":["hello.util.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"hello.util.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"hello.util","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();
    let os_module = br#"{"decls":[{"kind":"export","names":["hello.os.read"]},{"body":["os.fs.read_file",["bytes.lit","arch/never_exists.txt"]],"kind":"defn","name":"hello.os.read","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"hello.os","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();

    let tar = make_tar_with_package_with_modules(
        "hello",
        "0.1.0",
        Some(serde_json::json!({
            "determinism_tier": "mixed",
            "worlds_allowed": ["solve-pure", "run-os"]
        })),
        vec![("hello.util", pure_module), ("hello.os", os_module)],
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn facets_are_exposed_in_catalog_search_and_package_views() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;
    let module = br#"{"decls":[{"kind":"export","names":["svc.runtime.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"svc.runtime.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"svc.runtime","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();
    let tar = make_tar_with_package_with_modules(
        "ext-db-postgres",
        "0.1.0",
        Some(serde_json::json!({
            "archetypes": ["api-cell"],
            "runtimes": ["native-http"],
            "bindings": ["postgres", "otlp"],
            "trust_profile": "standard"
        })),
        vec![("svc.runtime", module)],
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let catalog = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/index/catalog.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    let catalog_facets = catalog["packages"][0]["facets"]
        .as_array()
        .expect("catalog facets");
    assert!(catalog_facets
        .iter()
        .any(|facet| facet == "binding:postgres"));
    assert!(catalog_facets
        .iter()
        .any(|facet| facet == "runtime:native-http"));
    assert!(catalog_facets.iter().any(|facet| facet == "trust:standard"));

    let search = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/search?q=postgres")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    let search_facets = search["packages"][0]["facets"]
        .as_array()
        .expect("search facets");
    assert!(search_facets
        .iter()
        .any(|facet| facet == "capability:database"));
    assert!(search_facets.iter().any(|facet| facet == "binding:otlp"));

    let metadata = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/packages/ext-db-postgres/0.1.0/metadata")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    let metadata_facets = metadata["facets"].as_array().expect("metadata facets");
    assert!(metadata_facets
        .iter()
        .any(|facet| facet == "archetype:api-cell"));

    let detail = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/packages/ext-db-postgres")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    let detail_facets = detail["facets"].as_array().expect("detail facets");
    assert!(detail_facets
        .iter()
        .any(|facet| facet == "binding:postgres"));
    assert!(detail_facets
        .iter()
        .any(|facet| facet == "runtime:native-http"));
}

#[tokio::test]
async fn archetypes_endpoint_groups_latest_packages() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;
    let module = br#"{"decls":[{"kind":"export","names":["svc.runtime.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"svc.runtime.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"svc.runtime","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();

    for (name, version, archetypes) in [
        ("ext-service-api", "0.1.0", serde_json::json!(["api-cell"])),
        (
            "ext-service-worker",
            "0.1.0",
            serde_json::json!(["event-consumer", "api-cell"]),
        ),
        (
            "ext-service-job",
            "0.1.0",
            serde_json::json!(["scheduled-job"]),
        ),
    ] {
        let tar = make_tar_with_package_with_modules(
            name,
            version,
            Some(serde_json::json!({
                "archetypes": archetypes,
                "runtimes": ["native-http"]
            })),
            vec![("svc.runtime", module.clone())],
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/packages/publish")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::from(tar))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let archetypes = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/archetypes")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    assert_eq!(archetypes["ok"], true);
    assert_eq!(archetypes["total"], 3);
    let api_cell = archetypes["archetypes"]
        .as_array()
        .expect("archetype list")
        .iter()
        .find(|item| item["archetype"] == "api-cell")
        .expect("api-cell entry");
    assert_eq!(api_cell["package_count"], 2);

    let filtered = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/archetypes?q=scheduled")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    assert_eq!(filtered["total"], 1);
    assert_eq!(filtered["archetypes"][0]["archetype"], "scheduled-job");

    let detail = read_body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/archetypes/api-cell")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
    )
    .await;
    assert_eq!(detail["archetype"], "api-cell");
    assert_eq!(detail["package_count"], 2);
    assert!(detail["packages"]
        .as_array()
        .expect("archetype packages")
        .iter()
        .any(|pkg| pkg["name"] == "ext-service-api"));
}

#[tokio::test]
async fn openapi_json_has_cache_headers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url,
        database_schema,
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/openapi/openapi.json")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(CACHE_CONTROL)
            .expect("cache-control")
            .to_str()
            .expect("cache-control str"),
        "public, max-age=3600"
    );
    let etag = resp
        .headers()
        .get(ETAG)
        .expect("etag")
        .to_str()
        .expect("etag str")
        .to_string();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!body.is_empty());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/openapi/openapi.json")
                .header(IF_NONE_MATCH, etag)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn publish_rejects_invalid_x07ast() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let tar = make_tar_with_package_with_module("hello", "0.1.0", b"not-json".to_vec());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(
        json["code"],
        Value::String("X07REG_PUBLISH_LINT_FAILED".to_string())
    );
    assert!(json["message"]
        .as_str()
        .expect("message str")
        .contains("invalid JSON"));
}

#[tokio::test]
async fn publish_rejects_missing_license() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let module_bytes = br#"{"decls":[{"kind":"export","names":["hello.util.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"hello.util.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"hello.util","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();
    let mut meta = serde_json::Map::new();
    meta.insert(
        "x07c_compat".to_string(),
        Value::String(">=0.1.111 <0.3.0".to_string()),
    );
    let manifest = serde_json::json!({
        "schema_version": "x07.package@0.1.0",
        "name": "hello",
        "description": "Test package used by x07-registry integration tests.",
        "docs": "This package exists for x07-registry tests.\n\nUsage:\n- x07 pkg add <name>@<version>\n",
        "version": "0.1.0",
        "module_root": "modules",
        "modules": ["hello.util"],
        "meta": Value::Object(meta),
    });
    let tar = make_tar_with_manifest_and_modules(manifest, vec![("hello.util", module_bytes)]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(
        json["code"],
        Value::String("X07REG_PKG_LICENSE_REQUIRED".to_string())
    );
}

#[tokio::test]
async fn publish_rejects_missing_x07c_compat() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let module_bytes = br#"{"decls":[{"kind":"export","names":["hello.util.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"hello.util.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"hello.util","schema_version":"x07.x07ast@0.3.0"}"#.to_vec();
    let manifest = serde_json::json!({
        "schema_version": "x07.package@0.1.0",
        "name": "hello",
        "description": "Test package used by x07-registry integration tests.",
        "license": "MIT OR Apache-2.0",
        "docs": "This package exists for x07-registry tests.\n\nUsage:\n- x07 pkg add <name>@<version>\n",
        "version": "0.1.0",
        "module_root": "modules",
        "modules": ["hello.util"],
    });
    let tar = make_tar_with_manifest_and_modules(manifest, vec![("hello.util", module_bytes)]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(
        json["code"],
        Value::String("X07REG_PKG_X07C_COMPAT_REQUIRED".to_string())
    );
}

#[tokio::test]
async fn publish_requires_token_when_configured() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let tar = make_tar_with_package("hello", "0.1.0");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .body(axum::body::Body::from(tar.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let token =
        create_user_with_token(&database_url, &database_schema, "tester", &["publish"]).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn tokens_owners_and_yank_flow_is_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let alice_token = create_user_with_token(
        &database_url,
        &database_schema,
        "alice",
        &["publish", "owner.manage"],
    )
    .await;
    let bob_token =
        create_user_with_token(&database_url, &database_schema, "bob", &["publish"]).await;
    let _webodik_token = create_user_with_token(
        &database_url,
        &database_schema,
        "webodik",
        &["publish", "owner.manage"],
    )
    .await;

    let tar = make_tar_with_package("hello", "0.1.0");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {alice_token}"))
                .body(axum::body::Body::from(tar.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/hello/owners")
                .header("Authorization", format!("Bearer {alice_token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"handle":"bob"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let tar = make_tar_with_package("hello", "0.2.0");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", format!("Bearer {bob_token}"))
                .body(axum::body::Body::from(tar.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=hel")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["packages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "hello"));
    assert_eq!(json["packages"][0]["is_official"], Value::Bool(false));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packages/hello/owners")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["is_official"], Value::Bool(false));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/hello/owners")
                .header("Authorization", format!("Bearer {alice_token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"handle":"webodik"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packages/hello/owners")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["is_official"], Value::Bool(true));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=hel")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["packages"][0]["is_official"], Value::Bool(true));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/packages/hello/owners/webodik")
                .header("Authorization", format!("Bearer {alice_token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packages/hello/owners")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["is_official"], Value::Bool(false));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/hello/owners")
                .header("Authorization", format!("Bearer {alice_token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"handle":"webodik"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=hel")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert_eq!(json["packages"][0]["is_official"], Value::Bool(true));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/hello/0.2.0/yank")
                .header("Authorization", format!("Bearer {alice_token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"yanked":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index/he/ll/hello")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let index_text = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .expect("index utf-8");
    assert!(index_text.contains("\"version\":\"0.2.0\""));
    assert!(index_text.contains("\"yanked\":true"));

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
        json["packages"][0]["latest"],
        Value::String("0.1.0".to_string())
    );
}

#[tokio::test]
async fn advisories_are_in_sparse_index_and_withdraw_hides_them() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        Vec::new(),
    ))
    .await;

    let token = create_user_with_token(
        &database_url,
        &database_schema,
        "tester",
        &["publish", "owner.manage"],
    )
    .await;

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

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/hello/0.1.0/advisories")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"kind":"broken","severity":"high","summary":"Version is broken."}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    let advisory_id = json["advisory"]["id"].as_str().expect("advisory id");
    assert_eq!(
        json["advisory"]["schema_version"],
        Value::String("x07.pkg.advisory@0.1.0".to_string())
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index/he/ll/hello")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let index_text = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .expect("index utf-8");
    let mut found = false;
    for line in index_text.lines() {
        let v: Value = serde_json::from_str(line).expect("parse ndjson line");
        if v["version"] == "0.1.0" {
            found = true;
            let advisories = v["advisories"].as_array().expect("advisories array");
            assert_eq!(advisories.len(), 1);
            assert_eq!(advisories[0]["id"], advisory_id);
            assert_eq!(advisories[0]["kind"], "broken");
            assert_eq!(advisories[0]["severity"], "high");
        }
    }
    assert!(found, "expected to find hello@0.1.0 index line");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/packages/hello/0.1.0/advisories/{advisory_id}/withdraw"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_body_json(resp.into_body()).await;
    assert!(json["advisory"]["withdrawn_at_utc"].is_string());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index/he/ll/hello")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let index_text = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .expect("index utf-8");
    for line in index_text.lines() {
        let v: Value = serde_json::from_str(line).expect("parse ndjson line");
        if v["version"] == "0.1.0" {
            assert!(v.get("advisories").is_none());
        }
    }
}

#[tokio::test]
async fn yank_via_session_requires_csrf_and_is_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (database_url, database_schema) = create_test_schema().await;
    let app = x07_registry::app_with_config(base_config(
        database_url.clone(),
        database_schema.clone(),
        x07_registry::RegistryStorageConfig::Filesystem {
            data_dir: tmp.path().to_path_buf(),
        },
        vec!["https://x07.io".to_string()],
    ))
    .await;

    let token = create_user_with_token(
        &database_url,
        &database_schema,
        "tester",
        &["publish", "owner.manage"],
    )
    .await;

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

    let (session_token, csrf_token) =
        create_session_for_user(&database_url, &database_schema, "tester").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/hello/0.1.0/yank")
                .header("Origin", "https://x07.io")
                .header("Cookie", format!("x07_session={session_token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"yanked":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/hello/0.1.0/yank")
                .header("Origin", "https://x07.io")
                .header("Cookie", format!("x07_session={session_token}"))
                .header("X-X07-CSRF", csrf_token)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"yanked":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
