mod api;
mod model;
mod config;
mod repository;

use actix_web::{web,web::Data, App, HttpServer,get};
//use api::user_api::{create_user, delete_user, get_all_users, get_user, update_user};
use api::routes;

use crate::config::config::Config;
use repository::mongodb_repo::MongoRepo;

pub struct AppState {
    db: Data<MongoRepo>,
    env: Config,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db = MongoRepo::init().await;
    let db_data = Data::new(db);

    let config = Config::init();

    println!("🚀 Server started successfully");


    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                db: db_data.clone(),
                env: config.clone(),
            }))
        .configure(routes::config)

    })
    .bind(("127.0.0.1", 8000))?
    .run()
    .await
}