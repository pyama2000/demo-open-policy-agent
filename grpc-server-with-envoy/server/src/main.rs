use serde::Serialize;
use tonic::{Request, Response, Status};

use crate::proto::{
    auth::v1::{
        auth_service_server::AuthServiceServer, SigninRequest, SigninResponse,
        FILE_DESCRIPTOR as AUTH_SERVICE_FILE_DESCRIPTOR,
    },
    misc::v1::{
        misc_service_server::MiscServiceServer, FILE_DESCRIPTOR as MISC_SERVICE_FILE_DESCRIPTOR,
    },
};

mod proto;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(AUTH_SERVICE_FILE_DESCRIPTOR)
        .register_encoded_file_descriptor_set(MISC_SERVICE_FILE_DESCRIPTOR)
        .build()?;

    let (_, health_service) = tonic_health::server::health_reporter();

    let addr = "0.0.0.0:50051".parse()?;
    println!("listening on: {}", &addr);
    tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(reflection_service)
        .add_service(AuthServiceServer::new(AuthService))
        .add_service(MiscServiceServer::new(MiscService))
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

enum Role {
    Admin,
    Guest,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Guest => write!(f, "guest"),
        }
    }
}

#[derive(Serialize)]
struct Claim {
    role: String,
}

impl Claim {
    fn new(role: Role) -> Self {
        Self {
            role: role.to_string(),
        }
    }
}

struct AuthService;

#[tonic::async_trait]
impl proto::auth::v1::auth_service_server::AuthService for AuthService {
    async fn signin(
        &self,
        req: Request<SigninRequest>,
    ) -> Result<Response<SigninResponse>, Status> {
        let req = req.into_inner();
        let role = match req.role() {
            proto::auth::v1::signin_request::Role::Unspecified => {
                return Err(Status::invalid_argument("invalid role"))
            }
            proto::auth::v1::signin_request::Role::Admin => Role::Admin,
            proto::auth::v1::signin_request::Role::Guest => Role::Guest,
        };

        let key = b"secret";
        let claim = Claim::new(role);
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claim,
            &jsonwebtoken::EncodingKey::from_secret(key),
        )
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SigninResponse { token }))
    }
}

struct MiscService;

#[tonic::async_trait]
impl proto::misc::v1::misc_service_server::MiscService for MiscService {
    async fn create(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Ok(Response::new(()))
    }

    async fn list(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Ok(Response::new(()))
    }
}
