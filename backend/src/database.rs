use mongodb::{
    bson::{doc, Document},
    IndexModel,
};

pub async fn initialize_client(uri: &str) -> mongodb::error::Result<mongodb::Client> {
    let client = mongodb::Client::with_uri_str(uri).await?;

    let db = client.database("av-api");
    let collection = db.collection::<Document>("malceiver");

    let index = IndexModel::builder()
        .keys(doc! { "sha256": 1 })
        .options(mongodb::options::IndexOptions::builder().build())
        .build();

    collection.create_index(index, None).await?;

    Ok(client)
}
