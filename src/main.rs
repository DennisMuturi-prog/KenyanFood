use std::sync::Arc;

use axum::{
    extract::State, response::{Html, IntoResponse, Redirect, Response}, routing::get, Form, Router
};
use tower_http::services::ServeDir;

struct AppState {
    db: PgPool,
}
#[tokio::main]
async fn main() {
    let db_connection_str = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost/database".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_connection_str)
        .await
        .expect("can't connect to database");
    let app_state = Arc::new(AppState { db: pool });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
        .await
        .unwrap();

    let app = Router::new()
        .route("/", get(root))
        .route("/login", get(login).post(post_login))
        .route("/signup", get(signup).post(post_signup))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(app_state);

    axum::serve(listener, app).await.unwrap();
}

async fn root() -> Result<Response, AppError> {
    let html_string = HomeTemplate.render()?;
    Ok(Html(html_string).into_response())
}

async fn login() -> Result<Response, AppError> {
    let html_string = LoginTemplate.render()?;
    Ok(Html(html_string).into_response())
}

async fn signup() -> Result<Response, AppError> {
    let html_string = SignUpTemplate.render()?;
    Ok(Html(html_string).into_response())
}

async fn post_signup(
    State(app_state): State<Arc<AppState>>,
    AppJson(user_data): AppJson<UserFormModel>,
) -> Result<Response, AppError> {
    println!("{:?}", user_data);
    let _ = user_data.validate()?;
    add_user(&app_state.db, user_data.email, user_data.password).await?;
    let html_string = RedirectTemplate.render()?;
    Ok(Html(html_string).into_response())
}

async fn post_login(
    State(app_state): State<Arc<AppState>>,
    Form(user_form): Form<LoginFormModel>,
) -> Result<Response, AppError> {
    let _ = user_form.validate()?;
    let is_valid = authenticate_user(&app_state.db, user_form.email, user_form.password).await?;
    if is_valid {
        let html_string = RedirectTemplate.render()?;
        Ok(Html(html_string).into_response())
    }else{
        let html_string = ErrorTemplate{
            error_messages:vec![ErrorMessage{
                field:"error".to_string(),
                form_error_messages:vec!["invalid email or password".to_string()]
            }]
        }.render()?;
        Ok(Html(html_string).into_response())

    }
}
use askama::Template;

#[derive(Template)]
#[template(path = "pages/landingpage.html")]
struct HomeTemplate;

#[derive(Template)]
#[template(path = "pages/login.html")]
struct LoginTemplate;

#[derive(Template)]
#[template(path = "pages/SignUp.html")]
struct SignUpTemplate;

#[derive(Template)]
#[template(path = "pages/redirect.html")]
struct RedirectTemplate;

use kenyan_food::{add_user, authenticate_user, AppError, AppJson, ErrorMessage, ErrorTemplate};
use serde::Deserialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use validator::Validate;

// pub static PASSWORD_RX: LazyLock<Regex> = LazyLock::new(|| {
//     Regex::new(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$").unwrap()
// });

#[derive(Debug, Deserialize, Validate)]
pub struct UserFormModel {
    #[validate(email(message = "invalid email"))]
    pub email: String,
    // #[validate(regex(path = *PASSWORD_RX))]
    pub password: String,
    #[validate(must_match(other = "password", message = "the password is not matching"))]
    pub confirm_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginFormModel {
    #[validate(email(message = "invalid email"))]
    pub email: String,
    // #[validate(regex(path = *PASSWORD_RX))]
    pub password: String,
}
