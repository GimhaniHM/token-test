mod api;
mod model;
mod config;
mod repository;

use actix_web::{web,web::Data, App, HttpServer,get};
//use api::user_api::{create_user, delete_user, get_all_users, get_user, update_user};
use api::routes;

use crate::config::config::Config;
use repository::mongodb_repo::MongoRepo;
use actix_cors::Cors;
use actix_web::middleware::Logger;

use dotenv::dotenv;

pub struct AppState {
    db: Data<MongoRepo>,
    env: Config,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    dotenv().ok();
    env_logger::init();

    let db = MongoRepo::init().await;
    let db_data = Data::new(db);

    let config = Config::init();

    println!("🚀 Server started successfully");


    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
            ])
            .supports_credentials();
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