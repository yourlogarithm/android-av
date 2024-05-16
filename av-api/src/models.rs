use axum::body::Bytes;
use derive_getters::Getters;
use serde::{Deserialize, Serialize};

use crate::utils;

#[derive(Debug, Getters)]
pub struct ScanFile {
    pub sha256: String,
    data: Bytes,
}

impl ScanFile {
    pub fn new(data: Bytes) -> Self {
        Self {
            sha256: utils::sha256(&data),
            data,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub sha256: String,
    pub prediction: Prediction,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Prediction {
    #[serde(rename = "det")]
    pub detection: Detection,
    #[serde(rename = "proba")]
    pub probability: f32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Detection {
    Adware,
    Banking,
    Benign,
    Riskware,
    Sms,
}

impl TryFrom<usize> for Detection {
    type Error = usize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Detection::Adware),
            1 => Ok(Detection::Banking),
            2 => Ok(Detection::Benign),
            3 => Ok(Detection::Riskware),
            4 => Ok(Detection::Sms),
            other => Err(other),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MalceiverDocument {
    pub sha256: String,
    pub prediction: Prediction,
    pub timestamp: mongodb::bson::DateTime,
}

#[derive(Debug, Deserialize)]
pub struct ProjectedMalceiverDocument {
    pub sha256: String,
    pub prediction: Prediction,
}
