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
use tracing::{info, error};
use tower_http::cors::{Any, CorsLayer};
use rayon::prelude::*;

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
    info!("Received scan request...");
    let mut files = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();
        files.push((name, data));
    }
    let (names, apks): (Vec<_>, Vec<_>) = files.into_par_iter().filter_map(|(name, data)| {
        if data.starts_with(b"PK") {
            let cursor = std::io::Cursor::new(data);
            match dexompiler::parse(cursor) {
                Ok(apk) => Some((name, apk)),
                Err(e) => {
                    error!("Error - {e}");
                    None
                },
            }
        } else {
            None
        }
    })
    .unzip();
    info!("Scanning {} APKs...", apks.len());
    match malceiver.predict(&apks) {
        Ok(predictions) => {
            let values = names.into_iter().zip(predictions.into_iter()).collect();
            info!("Scan completed successfully!");
            Json(ApiResponse::Success(values))
        },
        Err(e) => {
            error!("Error - {e}");
            Json(ApiResponse::Error(e.to_string()))
        },
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let malceiver = Arc::new(prediction::Malceiver::new());
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    let app = Router::new()
        .route("/", get(root))
        .route(
            "/scan",
            post(scan).layer(DefaultBodyLimit::max(1024 * 1024 * 1024)),
        )
        .with_state(malceiver)
        .layer(cors);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8888").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
