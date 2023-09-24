use crate::{model::user_model::{User, RegisterUserSchema, LoginUserSchema}, AppState};
use serde_json::json;

use actix_web::{
    post,get,
    web,
    web::{Data, Json, Path, service},
    HttpResponse,
    Responder,
    http::StatusCode,
};


use mongodb::bson::oid::ObjectId;
use chrono::{prelude::*, Duration};

//route handler function
#[get("/healthchecker")]
async fn index() -> impl Responder {
    const MESSAGE: &str = "JWT Authentication in Rust using Actix-web, mongodb";
    HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": MESSAGE}))
}

#[post("/user")]
pub async fn create_user(data: web::Data<AppState>, new_user: Json<User>) -> HttpResponse {
    let db = data.db.clone();
    let data = User {
        id: None,
        name: new_user.name.to_owned(),
        location: new_user.location.to_owned(),
        title: new_user.title.to_owned(),
        email: new_user.email.to_owned(),
        password: new_user.password.to_owned(),
        birth_date: new_user.birth_date.to_owned(),
        phone: new_user.phone.to_owned(),
        created_at: None,
    };

    let user_detail = db.create_user(data).await;

    match user_detail {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[post("/login")]
pub async fn login_user(data: web::Data<AppState>, user: Json<LoginUserSchema>) -> HttpResponse {
    let db = data.db.clone();

    let login_detail = db.login_user(user.into_inner());

    match login_detail.await {
        Ok(user) => HttpResponse::Ok().json(login_detail),
        Err(_) => HttpResponse::Ok()
            .status(StatusCode::from_u16(401).unwrap())
            .json(login_detail.await.unwrap_err()),
    }
}

// #[post("/register")]
// pub async fn register_user(data: web::Data<AppState>, new_user: Json<User>) -> HttpResponse {
//     let db = data.db.clone();
    
// }

// fn filter_user_record(user: &User) -> FilteredUser {
//     FilteredUser {
//         id: user.id.to_string(),
//         email: user.email.to_owned(),
//         name: user.name.to_owned(),
//         photo: user.photo.to_owned(),
//         role: user.role.to_owned(),
//         verified: user.verified,
//         createdAt: user.created_at.unwrap(),
//         updatedAt: user.updated_at.unwrap(),
//     }
// }

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(create_user)
        .service(index)
        .service(login_user);
}