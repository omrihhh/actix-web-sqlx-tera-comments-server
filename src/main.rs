use serde;
use dotenv::dotenv;
use std::env;
use actix_rt;
use sqlx::PgPool;
use actix_web::{error, middleware, web, App, Error, HttpResponse, HttpServer, Responder, Result};
use tera::Tera;
use anyhow;
use actix_web::dev::ServiceRequest;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::middleware::HttpAuthentication;


async fn validator(req: ServiceRequest, credentials: BearerAuth,) -> Result<ServiceRequest> {
    if credentials.token() == "example_token"{
        return Ok(req);
    }
    return Err(error::ErrorBadRequest("invalid_token"));
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Comment{
    comment: String
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Id{
    id: i64
}

#[derive(serde::Serialize, serde::Deserialize ,Debug)]
struct CommentOutput{
    comment: String,
    id: i64
}

struct AppData{
    tera: tera::Tera,
    pool: sqlx::PgPool
}

async fn index(data: web::Data<AppData>) -> Result<HttpResponse, Error> {

    let pool: PgPool = data.pool.clone();

    let res = sqlx::query!(
    r#"
        SELECT * FROM comments
    "#)
    .fetch_all(&pool)
    .await.unwrap();
    let mut v: Vec<CommentOutput> = Vec::new();
    for i in res {
        let t: CommentOutput = CommentOutput{comment: i.comment.unwrap(),id: i.id};
        v.push(t);
    }
    println!("{:?}", v);
    let mut ctx = tera::Context::new();
        ctx.insert("comments", &v);

    let s = data.tera.render("comments.html", &ctx)
            .map_err(|e| {println!("{}", e);error::ErrorInternalServerError("Template error")})?;
    Ok(HttpResponse::Ok().content_type("text/html").body(s))
}

async fn comment(parms: web::Form<Comment>, data: web::Data<AppData>) -> impl Responder {

    if parms.comment != ""{
        let pool: PgPool = data.pool.clone();
        sqlx::query!(r#"
                INSERT INTO comments (comment) VALUES ($1) RETURNING comment
            "#
            ,parms.comment
        )
            .fetch_one(&mut &pool)
            .await.unwrap();  
    }
    "ok"
}

async fn delete(parms: web::Form<Id>, data: web::Data<AppData>) -> impl Responder {

    let pool: PgPool = data.pool.clone();
    sqlx::query!(r#"
            DELETE FROM comments WHERE id = $1 RETURNING comment
        "#
        ,parms.id
    )
        .fetch_one(&mut &pool)
        .await.unwrap();

    "ok"
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {

    dotenv().ok();
    env_logger::init();

    std::env::set_var("RUST_LOG", "actix_web=info");

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let db_pool = PgPool::new(&database_url).await?;

    HttpServer::new(move || {
        let tera =
            Tera::new(concat!("src", "/templates/*")).unwrap();

        let auth = HttpAuthentication::bearer(validator); 

        App::new()
            .data(AppData{
                tera: tera,
                pool: db_pool.clone()
            })
            .wrap(middleware::Logger::default())
            .service(web::resource("/").route(web::get().to(index)))
            .service(web::scope("api")
                .wrap(auth)
                .service(web::resource("/comment").route(web::post().to(comment)))
                .service(web::resource("/delete").route(web::post().to(delete)))
            )
    })
    .bind(&format!("0.0.0.0:{}",env::var("PORT").unwrap()))?
    .workers(6)
    .run()
    .await?;

    Ok(())
}
