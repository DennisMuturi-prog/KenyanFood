use askama::Template;
use axum::{
    extract::{
        FromRequest,
        rejection::{FormRejection, JsonRejection},
    },
    http::{StatusCode, header::InvalidHeaderValue},
    response::{Html, IntoResponse, Response},
};
use serde::Serialize;
use sqlx::PgPool;
use thiserror::Error;
use validator::{ValidationErrors, ValidationErrorsKind};
pub mod auth;
pub mod init;
pub mod middleware;
pub mod recipes;

#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct AppJson<T>(pub T);

impl<T> IntoResponse for AppJson<T>
where
    axum::Json<T>: IntoResponse,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

#[derive(FromRequest)]
#[from_request(via(axum::Form), rejection(AppError))]
pub struct AppForm<T>(pub T);

impl<T> IntoResponse for AppForm<T>
where
    axum::Form<T>: IntoResponse,
{
    fn into_response(self) -> Response {
        axum::Form(self.0).into_response()
    }
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("trouble rendering html")]
    RenderingError(#[from] askama::Error),

    #[error("json format not matching")]
    JsonRejection(#[from] JsonRejection),

    #[error("form data not matching")]
    FormRejection(#[from] FormRejection),

    #[error("validation error")]
    FormValidationError(#[from] ValidationErrors),

    #[error("JwT errors")]
    JWTError(#[from] jsonwebtoken::errors::Error),

    #[error("data error")]
    DataError(#[from] DataError),

    #[error("header errors")]
    InvalidHeader(#[from] InvalidHeaderValue),

    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorResponse {
            message: String,
        }
        let (status, message) = match self {
            AppError::JsonRejection(rejetion) => {
                tracing::error!("json rejection:{}", rejetion);
                (rejetion.status(), rejetion.body_text())
            }
            AppError::FormRejection(rejetion) => {
                tracing::error!("form rejection:{}", rejetion);
                (rejetion.status(), rejetion.body_text())
            }
            AppError::JWTError(jwt_error) => {
                tracing::error!("jwt error :{}", jwt_error);

                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("Something went wrong"),
                )
            }
            AppError::InvalidHeader(header_error) => {
                tracing::error!("invalid header:{}", header_error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("Something went wrong"),
                )
            }
            AppError::SerdeJsonError(serde_json_error) => {
                tracing::error!("serde json rejection:{}", serde_json_error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("Something went wrong"),
                )
            }
            AppError::RenderingError(render_error) => {
                tracing::error!("rendering error:{}", render_error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("Something went wrong"),
                )
            }
            AppError::DataError(data_error) => match data_error {
                DataError::FailedQuery(reason) => {
                    let error_messages = vec![reason];
                    let email_error = ErrorMessage {
                        field: String::from("email"),
                        form_error_messages: error_messages,
                    };

                    let error_messages = vec![email_error];
                    let template = ErrorTemplate { error_messages };
                    return match template.render() {
                        Ok(html) => Html(html).into_response(),
                        Err(err) => {
                            tracing::error!("rendering error:{}", err);
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Failed to render template. Error: {err}"),
                            )
                                .into_response()
                        }
                    };
                }
                DataError::Query(query_error) => {
                    tracing::error!("database query error:{}", query_error);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        String::from("Something went wrong"),
                    )
                }
                e => {
                    tracing::error!("data error:{}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        String::from("Something went wrong"),
                    )
                }
            },
            AppError::FormValidationError(validation_errors) => {
                let validation_errors = extract_validation_errors(validation_errors);
                let template = ErrorTemplate {
                    error_messages: validation_errors,
                };
                return match template.render() {
                    Ok(html) => Html(html).into_response(),
                    Err(err) => {
                        tracing::error!("rendering error::{}", err);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to render template. Error: {err}"),
                        )
                            .into_response()
                    }
                };
            }
        };
        (status, AppJson(ErrorResponse { message })).into_response()
    }
}

#[derive(Debug)]
pub struct ErrorMessage {
    pub field: String,
    pub form_error_messages: Vec<String>,
}
fn extract_validation_errors(validation_errors: ValidationErrors) -> Vec<ErrorMessage> {
    validation_errors
        .0
        .iter()
        .map(|(key, value)| {
            let error_messages: Vec<String> = match value {
                ValidationErrorsKind::Field(validation_errors) => validation_errors
                    .iter()
                    .filter_map(|current_message| current_message.message.to_owned())
                    .map(|message| message.to_string())
                    .collect(),
                _ => Vec::new(),
            };
            ErrorMessage {
                field: key.to_string(),
                form_error_messages: error_messages,
            }
        })
        .collect()
}

#[derive(Template)]
#[template(path = "pages/formErrors.html")]
pub struct ErrorTemplate {
    pub error_messages: Vec<ErrorMessage>,
}
use argon2::{
    Argon2,
    password_hash::{
        self, PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    Ok(password_hash)
}

pub async fn add_user(pool: &PgPool, email: &str, password: &str) -> Result<(), DataError> {
    let password_hash = hash_password(password)?;
    let bytes_hash = password_hash.as_bytes();
    sqlx::query!(
        "INSERT INTO users(email,password)
        VALUES($1,$2)",
        email,
        bytes_hash
    )
    .execute(pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(database_error) => {
            if database_error.constraint() == Some("users_email_key") {
                DataError::FailedQuery(String::from("email is already taken"))
            } else {
                DataError::Internal(String::from("an error occurred while adding"))
            }
        }
        e => DataError::Query(e),
    })?;

    Ok(())
}

pub async fn authenticate_user(
    pool: &PgPool,
    email: &str,
    password: String,
) -> Result<bool, DataError> {
    let password = password.as_bytes();
    let user = sqlx::query!("SELECT email,password FROM users WHERE email=$1", email)
        .fetch_one(pool)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::RowNotFound => {
                DataError::FailedQuery("that account does not exist".to_string())
            }
            e => DataError::Query(e),
        })?;
    let hashed_password = String::from_utf8(user.password)?;
    let parsed_hash = PasswordHash::new(&hashed_password)?;
    let is_password_valid = Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok();
    Ok(is_password_valid)
}
#[derive(Error, Debug)]
pub enum DataError {
    #[error("Failed database query: {0}")]
    Query(#[from] sqlx::Error),

    #[error("Failed to query: {0}")]
    FailedQuery(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Failed to convert from utf8: {0}")]
    Utf8Conversion(#[from] std::string::FromUtf8Error),

    #[error("hashing error")]
    PasswordHashingError(argon2::password_hash::Error),
}

impl From<password_hash::Error> for DataError {
    fn from(hash_error: password_hash::Error) -> Self {
        Self::PasswordHashingError(hash_error)
    }
}
