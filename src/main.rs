#[tokio::main]
async fn main() {
    let bind = std::env::var("X07_REGISTRY_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    axum::serve(listener, x07_registry::app().await)
        .await
        .expect("serve");
}
