#![feature(array_chunks)]

mod database;
mod models;
mod prediction;
mod state;
mod utils;

use std::collections::HashMap;

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use futures::StreamExt;
use models::ProjectedMalceiverDocument;
use mongodb::{bson::doc, options::{FindOneOptions, FindOptions}};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use state::AppState;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};

use crate::models::{MalceiverDocument, ScanFile, ScanResponse};

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
async fn query(State(state): State<AppState>, Path(hash): Path<String>) -> (StatusCode, Json<ApiResponse<ScanResponse>>) {
    info!("Received query request...");
    let filter = doc! { "sha256": hash };
    let options = FindOneOptions::builder()
        .projection(doc! { "sha256": 1, "prediction": 1 })
        .build();
    match state
        .client
        .database("av-api")
        .collection::<ProjectedMalceiverDocument>("malceiver")
        .find_one(filter, options)
        .await
    {
        Ok(Some(ProjectedMalceiverDocument { sha256, prediction })) => {
            info!("Query completed successfully!");
            (StatusCode::OK, Json(ApiResponse::Success(ScanResponse { sha256, prediction })))
        }
        Ok(None) => {
            info!("Query completed successfully!");
            (StatusCode::NOT_FOUND, Json(ApiResponse::Error("Not found".to_string())))
        }
        Err(e) => {
            error!("Error - {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::Error(e.to_string())))
        }
    }
}

#[axum::debug_handler]
async fn scan(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Json<ApiResponse<Vec<ScanResponse>>> {
    info!("Received scan request...");
    let mut files = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        match field.bytes().await {
            Ok(data) => {
                if data.starts_with(b"PK") {
                    files.push(ScanFile::new(data))
                }
            }
            Err(e) => {
                error!("Error - {e}");
                return Json(ApiResponse::Error(e.to_string()));
            }
        }
    }
    info!("Files: {}", files.len());

    let hashes = files.iter().map(|f| f.sha256()).collect::<Vec<_>>();
    let filter = doc! { "sha256": { "$in": &hashes } };
    let options = FindOptions::builder()
        .projection(doc! { "sha256": 1, "prediction": 1 })
        .build();
    let cached = match state
        .client
        .database("av-api")
        .collection::<ProjectedMalceiverDocument>("malceiver")
        .find(filter, options)
        .await
    {
        Ok(mut cursor) => {
            let mut result = HashMap::with_capacity(hashes.len());
            while let Some(document) = cursor.next().await {
                match document {
                    Ok(ProjectedMalceiverDocument { sha256, prediction }) => {
                        result.insert(sha256, prediction);
                    }
                    Err(e) => error!("MongoDB document retrieval failed - {e}"),
                }
            }
            result
        }
        Err(e) => {
            error!("MongoDB query failed - {e}");
            HashMap::new()
        }
    };
    info!("Cached predictions: {}", cached.len());

    if cached.len() == files.len() {
        return Json(ApiResponse::Success(
            cached
                .into_iter()
                .map(|(sha256, prediction)| ScanResponse { sha256, prediction })
                .collect(),
        ));
    }

    let (files, apks): (Vec<_>, Vec<_>) = files
            .into_par_iter()
            .filter_map(|file| {
                if cached.contains_key(file.sha256()) {
                    None
                } else {
                    let cursor = std::io::Cursor::new(file.data());
                    match dexompiler::parse(cursor) {
                        Ok(apk) => Some((file, apk)),
                        Err(e) => {
                            error!("Error - {e}");
                            None
                        }
                    }
                }
            })
            .unzip();

        info!("Scanning: {}", apks.len());
        match state.malceiver.predict(&apks) {
            Ok(predictions) => {
                let timestamp = mongodb::bson::DateTime::now();
                let values: Vec<_> = files
                    .into_iter()
                    .zip(predictions.into_iter())
                    .map(|(ScanFile { sha256, .. }, prediction)| MalceiverDocument {
                        sha256,
                        prediction,
                        timestamp,
                    })
                    .collect();
                let coll = state
                    .client
                    .database("av-api")
                    .collection::<MalceiverDocument>("malceiver");
                if let Err(e) = coll.insert_many(&values, None).await {
                    error!("MongoDB insertion failed - {e}");
                }
                let mut scan_results: Vec<_> = values
                    .into_iter()
                    .map(
                        |MalceiverDocument {
                             sha256, prediction, ..
                         }| ScanResponse { sha256, prediction },
                    )
                    .chain(
                        cached
                            .into_iter()
                            .map(|(sha256, prediction)| ScanResponse { sha256, prediction }),
                    )
                    .collect();
                scan_results.sort_by(|a, b| a.sha256.cmp(&b.sha256));
                info!("Scan completed successfully!");
                Json(ApiResponse::Success(scan_results))
            }
            Err(e) => {
                error!("Error - {e}");
                Json(ApiResponse::Error(e.to_string()))
            }
        }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let model_path = args.get(1).map(|s| s.as_str()).unwrap_or("/model.pb");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let state = AppState::new(model_path).await;

    let app = Router::new()
        .route("/", get(root))
        .route(
            "/scan",
            post(scan).layer(DefaultBodyLimit::max(1024 * 1024 * 1024)),
        )
        .route("/query/:hash", get(query))
        .with_state(state)
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:8000"))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
