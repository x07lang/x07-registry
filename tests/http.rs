use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

async fn read_body_json(body: axum::body::Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    serde_json::from_slice(&bytes).expect("parse json body")
}

fn make_tar_with_package(name: &str, version: &str) -> Vec<u8> {
    let manifest = serde_json::json!({
        "schema_version": "x07.package@0.1.0",
        "name": name,
        "version": version,
        "module_root": "modules",
        "modules": ["hello.util"],
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("encode manifest");

    let module_bytes = br#"{"decls":[{"kind":"export","names":["hello.util.answer"]},{"body":["bytes.alloc",0],"kind":"defn","name":"hello.util.answer","params":[],"result":"bytes"}],"imports":[],"kind":"module","module_id":"hello.util","schema_version":"x07.x07ast@0.1.0"}"#.to_vec();

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
            .append_data(&mut header, "x07-package.json", std::io::Cursor::new(&manifest_bytes))
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

#[tokio::test]
async fn healthz_is_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let app = x07_registry::app_with_config(x07_registry::RegistryConfig {
        data_dir: tmp.path().to_path_buf(),
        public_base: "http://127.0.0.1:8080".to_string(),
        auth_token: None,
    });
    let resp = app
        .oneshot(Request::builder().uri("/healthz").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn index_config_is_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let app = x07_registry::app_with_config(x07_registry::RegistryConfig {
        data_dir: tmp.path().to_path_buf(),
        public_base: "http://127.0.0.1:8080".to_string(),
        auth_token: None,
    });
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
    assert!(json["dl"].as_str().unwrap().ends_with("/v1/packages/"));
    assert!(json["api"].as_str().unwrap().ends_with("/v1/"));
}

#[tokio::test]
async fn publish_creates_index_and_download() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let app = x07_registry::app_with_config(x07_registry::RegistryConfig {
        data_dir: tmp.path().to_path_buf(),
        public_base: "http://127.0.0.1:8080".to_string(),
        auth_token: None,
    });

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

#[tokio::test]
async fn publish_requires_token_when_configured() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let app = x07_registry::app_with_config(x07_registry::RegistryConfig {
        data_dir: tmp.path().to_path_buf(),
        public_base: "http://127.0.0.1:8080".to_string(),
        auth_token: Some("secret".to_string()),
    });

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

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/packages/publish")
                .header("Authorization", "Bearer secret")
                .body(axum::body::Body::from(tar))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
