use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct LoginRequest {
    role: String,
}

#[derive(Serialize)]
struct Claim {
    role: String,
}

impl Claim {
    pub fn new(role: String) -> Self {
        Self { role }
    }
}

pub async fn login(Json(payload): Json<LoginRequest>) -> String {
    let key = b"secret";
    let claim = Claim::new(payload.role);
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claim,
        &jsonwebtoken::EncodingKey::from_secret(key),
    )
    .unwrap();
    token
}
