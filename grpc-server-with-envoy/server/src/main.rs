use crate::proto::{
    auth::v1::FILE_DESCRIPTOR as AUTH_SERVICE_FILE_DESCRIPTOR,
    misc::v1::FILE_DESCRIPTOR as MISC_SERVICE_FILE_DESCRIPTOR,
};

mod proto;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(AUTH_SERVICE_FILE_DESCRIPTOR)
        .register_encoded_file_descriptor_set(MISC_SERVICE_FILE_DESCRIPTOR)
        .build()?;

    let addr = "0.0.0.0:50051".parse()?;
    println!("listening on: {}", &addr);
    tonic::transport::Server::builder()
        .add_service(reflection_service)
        .serve_with_shutdown(addr, shutdown_signal())
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
