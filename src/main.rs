#![feature(array_chunks)]

mod prediction;

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{DefaultBodyLimit, Multipart, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use prediction::{Malceiver, Prediction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiResponse<T> {
    Success(T),
    Error(String),
}

async fn root() -> StatusCode {
    StatusCode::OK
}

#[axum::debug_handler]
async fn scan(
    State(malceiver): State<Arc<Malceiver>>,
    mut multipart: Multipart,
) -> Json<ApiResponse<HashMap<String, Prediction>>> {
    let mut names = Vec::new();
    let mut apks = Vec::new();
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();
        if data.starts_with(b"PK") {
            names.push(name);
            apks.push(data);
        }
    }
    match malceiver.predict(&apks) {
        Ok(predictions) => Json(ApiResponse::Success(
            names.into_iter().zip(predictions.into_iter()).collect(),
        )),
        Err(e) => Json(ApiResponse::Error(e.to_string())),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let malceiver = Arc::new(prediction::Malceiver::new());
    let app = Router::new()
        .route("/", get(root))
        .route(
            "/scan",
            post(scan).layer(DefaultBodyLimit::max(1024 * 1024 * 1024)),
        )
        .with_state(malceiver);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8888").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
