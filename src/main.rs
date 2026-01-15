#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind");
    axum::serve(listener, x07_registry::app())
        .await
        .expect("serve");
}

