use std::{borrow::Cow, sync::Arc};

use axum::{
    extract::{ Path, State}, http::{HeaderMap, HeaderValue}, middleware, response::{Html, IntoResponse, Response, Sse}, routing::get, Extension, Router
};
use async_stream::stream;
use pval::Pval;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use datastar::{axum::ReadSignals, prelude::{PatchElements, PatchSignals}};
use core::{convert::Infallible};

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
        .route(
            "/",
            get(root).layer(middleware::from_fn(authorization_middleware)),
        )
        .route("/login", get(login).post(post_login))
        .route("/signup", get(signup).post(post_signup))
        .route("/infinite_scroll", get(infinite_recipe_scroll))
        .route("/recipe/{id}", get(recipe_handler))
        .route("/search", get(search)) 
        .layer(CookieManagerLayer::new())
        .with_state(app_state);
    
    init::logging();

    axum::serve(listener, app).await.unwrap();
}

async fn root(
    Extension(current_user): Extension<CurrentUser>,
    State(app_state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    println!("done");
    let recipes = get_recipes(&app_state.db, 0).await?;
    let last_recipe_id = recipes.last().map(|recipe| recipe.id).unwrap_or(0);
    let html_string = HomeTemplate {
        email: current_user.email,
        recipes,
        last_recipe_id,
    }
    .render()?;

    Ok(Html(html_string).into_response())
}

async fn recipe_handler(
    State(app_state): State<Arc<AppState>>,
    Path(id):Path<i32>)->Result<Response,AppError>{
    let recipe=get_recipe_info(&app_state.db, id).await?;
    let html_str=RecipeInfoTemplate{
        recipe
    }.render()?;
    Ok(Html(html_str).into_response())

}

async fn search(
    State(app_state): State<Arc<AppState>>,
    ReadSignals(signals): ReadSignals<SearchSignals> 
)->Result<Response,AppError>{
    let recipes = search_recipes(&app_state.db, signals.search_term).await?;
    let html_string = InfiniteRecipeScrollTemplate {
        recipes
    }
    .render()?;

    let mut headers = HeaderMap::new();
    headers.insert("datastar-selector", HeaderValue::from_static("#recipes"));
    headers.insert("datastar-mode", HeaderValue::from_static("inner"));
    Ok((headers, Html(html_string)).into_response())

}

async fn infinite_recipe_scroll(
    State(app_state): State<Arc<AppState>>,
    ReadSignals(signals): ReadSignals<Signals>  
) -> Result<impl IntoResponse, AppError> {
    println!("fetch");
    let recipes = get_recipes(&app_state.db, signals.cursor).await?;
    
    let last_recipe_id = recipes.last().map(|recipe| recipe.id).unwrap_or(signals.cursor);
    let is_end_of_pagination=recipes.len()<10;
    let html_string = InfiniteRecipeScrollTemplate {
        recipes
    }
    .render()?;

    Ok(Sse::new(stream!{
        let patch_element=PatchElements::new(html_string).selector("#recipes").mode(datastar::consts::ElementPatchMode::Append);
        let signal_patch = format!(r#"{{"cursor":{}}}"#, last_recipe_id);
        let patch_signal=PatchSignals::new(signal_patch);
        let sse_event_element = patch_element.write_as_axum_sse_event();
        let sse_event_signal = patch_signal.write_as_axum_sse_event();
        if is_end_of_pagination{
            let end_patch_element=PatchElements::new_remove("").selector("#pagination");
            let sse_event_end_element=end_patch_element.write_as_axum_sse_event();
            yield Ok::<_, Infallible>(sse_event_end_element);
        }
        yield Ok::<_, Infallible>(sse_event_signal);
        yield Ok::<_, Infallible>(sse_event_element);

    }))

    
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
    cookies: Cookies,
    State(app_state): State<Arc<AppState>>,
    AppForm(user_data): AppForm<UserFormModel>,
) -> Result<Response, AppError> {
    user_data.validate()?;
    add_user(&app_state.db, &user_data.email, &user_data.password).await?;
    let token = encode_jwt(user_data.email)?;
    let cookie = Cookie::build(("auth_token", token))
        .http_only(true)
        .secure(true) // Only send over HTTPS in production
        .same_site(tower_cookies::cookie::SameSite::Strict)
        .path("/")
        .build();
    cookies.add(cookie);
    let html_string = RedirectTemplate.render()?;
    Ok(Html(html_string).into_response())
}

async fn post_login(
    cookies: Cookies,
    State(app_state): State<Arc<AppState>>,
    AppForm(user_form): AppForm<LoginFormModel>,
) -> Result<Response, AppError> {
    user_form.validate()?;
    let is_valid = authenticate_user(&app_state.db, &user_form.email, user_form.password).await?;
    if is_valid {
        let token = encode_jwt(user_form.email)?;
        let cookie = Cookie::build(("auth_token", token))
            .http_only(true)
            .secure(true) // Only send over HTTPS in production
            .same_site(tower_cookies::cookie::SameSite::Strict)
            .path("/")
            .build();
        cookies.add(cookie);
        let html_string = RedirectTemplate.render()?;
        Ok(Html(html_string).into_response())
    } else {
        let html_string = ErrorTemplate {
            error_messages: vec![ErrorMessage {
                field: "error".to_string(),
                form_error_messages: vec!["invalid email or password".to_string()],
            }],
        }
        .render()?;
        Ok(Html(html_string).into_response())
    }
}
use askama::Template;

#[derive(Template)]
#[template(path = "pages/landingpage.html")]
struct HomeTemplate {
    email: String,
    recipes: Vec<Recipe>,
    last_recipe_id: i32,
}

#[derive(Template)]
#[template(path = "pages/recipe_details.html")]
struct RecipeInfoTemplate {
    recipe:RecipeDetails
}

#[derive(Template)]
#[template(path = "pages/more_recipe.html")]
struct InfiniteRecipeScrollTemplate {
    recipes: Vec<Recipe>,
}

#[derive(Template)]
#[template(path = "pages/login.html")]
struct LoginTemplate;

#[derive(Template)]
#[template(path = "pages/SignUp.html")]
struct SignUpTemplate;

#[derive(Template)]
#[template(path = "pages/redirect.html")]
struct RedirectTemplate;

use kenyan_food::{
    add_user, auth::encode_jwt, authenticate_user, init, middleware::{authorization_middleware, CurrentUser}, recipes::{get_recipe_info, get_recipes, search_recipes, Recipe, RecipeDetails}, AppError, AppForm, ErrorMessage, ErrorTemplate
};
use serde::Deserialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
pub struct UserFormModel {
    #[validate(email(message = "invalid email"))]
    pub email: String,
    #[validate(custom(function="validate_password"))]
    pub password: String,
    #[validate(must_match(other = "password", message = "the password is not matching"))]
    pub confirm_password: String,
}


#[derive(Deserialize)]
pub struct Signals {
    pub cursor: i32,
}

#[derive(Deserialize)]
pub struct SearchSignals {
    pub search_term: String,
}

#[derive(Debug, Deserialize)]
pub struct Paging {
    pub cursor: i32,
}
#[derive(Debug, Deserialize, Validate)]
pub struct LoginFormModel {
    #[validate(email(message = "invalid email"))]
    pub email: String,
    pub password: String,
}


fn validate_password(password:&str)->Result<(), ValidationError>{
    let validator = Pval::new()
        .min_length(8)
        .require_uppercase(true)
        .require_lowercase(true)
        .require_digit(true)
        .require_special(true)
        .build();

    validator.validate(password).map_err(|err|ValidationError::new("weak_password").with_message(Cow::Owned(err)))?;
    Ok(())
    
}