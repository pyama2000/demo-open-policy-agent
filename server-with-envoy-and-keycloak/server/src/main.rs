use axum::http::StatusCode;
use axum::routing::{get, post};

mod handler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = axum::Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/auth/login", post(handler::login));
    let port = std::env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port).parse()?;
    println!("listening on: {}", &addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .unwrap_or_else(|e| panic!("failed to install Ctrl+C handler: {}", e))
    };

    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|e| panic!("failed to install singal handler: {}", e))
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => println!("receive ctrl_c signal"),
        _ = terminate => println!("receive terminate"),
    }

    println!("signal received, starting graceful shutdown");
}
