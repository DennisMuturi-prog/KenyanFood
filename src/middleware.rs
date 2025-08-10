use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use tower_cookies::Cookies;

use crate::{AppError, auth::decode_jwt};

#[derive(Clone)]
pub struct CurrentUser {
    pub email: String,
}

pub async fn authorization_middleware(
    cookies: Cookies,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = cookies.get("auth_token");
    let token = match token {
        Some(auth_token) => auth_token.value().to_string(),
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let token_data = decode_jwt(token);
    let token_data = match token_data {
        Ok(token_claim) => token_claim,
        Err(_) => return Ok(Redirect::to("/login").into_response()),
    };

    req.extensions_mut().insert(CurrentUser {
        email: token_data.claims.email,
    });

    Ok(next.run(req).await)
}
