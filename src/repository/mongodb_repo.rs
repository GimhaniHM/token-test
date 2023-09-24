use std::env;
extern crate dotenv;
use actix_web::{HttpRequest, HttpResponse, Responder};
use chrono::Utc;

// use crypto::digest::Digest;
// use crypto::sha2::Sha256;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
//use bcrypt::{hash, DEFAULT_COST};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use chrono::{DateTime, Duration, Utc};
use crypto::digest::Digest;
use crypto::sha2::Sha256;

use dotenv::dotenv;

use futures::stream::TryStreamExt;

use mongodb::{
    bson::{doc ,extjson::de::Error, oid::ObjectId},
    results::{DeleteResult, InsertOneResult, UpdateResult},
    Client, Collection,
};

use crate::model::user_model::{User, RegisterUserSchema, LoginUserSchema, TokenClaims};
use crate::model::response::{LoginResponse, Response};

crate::config::config;

pub struct MongoRepo {
    col: Collection<User>,
}

impl MongoRepo {
    pub async fn init() -> Self {
        dotenv().ok();

        let uri = match env::var("MONGOURI") {
            Ok(v) => v.to_string(),
            Err(_) => format!("Error loading env variables"),
        };

        let client = Client::with_uri_str(uri).await.expect("Error connecting to database");

        let db = client.database("user-db");
        let col: Collection<User> = db.collection("user");

        println!("✅ Database connected successfully");

        MongoRepo {col}
    }

    pub async fn create_user(&self, new_user: User) -> Result<InsertOneResult, Error> {
        let new_data = User {
            id: None,
            name: new_user.name,
            location: new_user.location,
            title: new_user.title,
            email: new_user.email,
            password: new_user.password,
            birth_date: new_user.birth_date,
            phone: new_user.phone,
            created_at: Some(Utc::now()),
        };

        let user = self
            .col
            .insert_one(new_data, None)
            .await
            .ok()
            .expect("Error creating user");

        Ok(user)
    }

    pub async fn find_user_with_email(&self, email: &str) -> Result<Option<User>, Error> {
        let filter = doc! {"email": email};
        let user_detail = self
            .col
            .find_one(filter, None)
            .await
            .ok()
            .expect("Error getting user's details");

        Ok(user_detail)
    }

    pub async fn login_user (&self, user: LoginUserSchema) -> Result<LoginResponse, Response> {
        match self.find_user_with_email(&user.email.to_string()).await.unwrap() {
            Some(x) => {
                let mut sha = Sha256::new();
                sha.input_str(user.password.as_str());
                if x.password == sha.result_str() {
                    // JWT
                    let _config: Config = Config {};
                    let _var = _config.get_config_with_key("SECRET_KEY");
                    let key = _var.as_bytes();

                    let mut _date: DateTime<Utc>;
                    // Remember Me
                    if !user.remember_me {
                        _date = Utc::now() + Duration::hours(1);
                    } else {
                        _date = Utc::now() + Duration::days(365);
                    }
                    let my_claims = TokenClaims {
                        sub: user.email,
                        exp: _date.timestamp() as usize,
                    };
                    let token = encode(
                        &Header::default(),
                        &my_claims,
                        &EncodingKey::from_secret(key),
                    )
                        .unwrap();
                    Ok(LoginResponse {
                        status: true,
                        token,
                        message: "You have successfully logged in.".to_string(),
                    })
                } else {
                    Err(Response {
                        status: false,
                        message: "Check your user informations.".to_string(),
                    })
                }
            }
            None => Err(Response {
                status: false,
                message: "Check your user informations.".to_string(),
            }),
        }
    }

    /*
    pub async fn register(&self, user: User) -> HttpResponse {
        // Check if a user with the provided email already exists in the database
        let user_exits = self.user_exists_by_email(&user.email.to_string()).await.unwrap();

        if user_exits.is_some() {
            return HttpResponse::Conflict().json(
                serde_json::json!({"status": "fail","message": "User with that email already exists"}),
            );
        }
        
        //hash the pasword
        let salt = SaltString::generate(&mut OsRng);
        let hashed_password = Argon2::default()
            .hash_password(user.password.as_bytes(), &salt)
            .expect("Error while hashing password")
            .to_string();

        }

        //construct a new User instance with the hashed password
        let new_data = User {
            id: None,
            name: new_user.name,
            location: new_user.location,
            title: new_user.title,
            email: new_user.email,
            password: new_user.password,
            birth_date: new_user.birth_date,
            phone: new_user.phone,
            created_at: Some(Utc::now()),
        };

        match self.col.insert_one(new_data, None).await {
            Ok(user) => HttpResponse::Ok().json(user),
            Err(e) => HttpResponse::InternalServerError().json(
                serde_json::json!({"status": "error","message": format!("{:?}", e)}),
            ),
        }

         */



}






