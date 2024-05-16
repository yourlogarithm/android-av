use std::sync::Arc;

use crate::{database::initialize_client, prediction::Malceiver};

#[derive(Clone)]
pub struct AppState {
    pub client: mongodb::Client,
    pub malceiver: Arc<Malceiver>,
}

impl AppState {
    pub async fn new(model_path: &str) -> Self {
        let uri = std::env::var("MONGO_URI").expect("MONGO_URI must be set");
        let client = initialize_client(&uri).await.unwrap();
        let malceiver = Arc::new(Malceiver::new(model_path));
        Self { client, malceiver }
    }
}
