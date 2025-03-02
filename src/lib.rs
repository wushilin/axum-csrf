use axum::{body::Body, extract::{OptionalFromRequestParts, Request}, http::{self, request::Parts, HeaderValue, Method, StatusCode, Uri}, middleware::Next, response::{IntoResponse, Response}, Json};
use hex::encode;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use short_uuid::short;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tower_cookies::Cookie;
use std::convert::Infallible;
use lazy_static::lazy_static;
use rand::{rng, Rng};
use rand::distr::Alphanumeric;

type HmacSha256 = Hmac<Sha256>;

lazy_static! {
    static ref KEY:Arc<RwLock<String>> = Arc::new(RwLock::new(generate_random_string(32)));
    static ref SECURE_COOKIE: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
}

/// Generate a random string of size
/// Possible keys are from alpha numeric, mixing upper/lower cases
pub fn generate_random_string(length: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Enable or disable secure cookie. Default is to disable so it works with HTTP and HTTPS.
/// Enabling secure cookie will make it only works with HTTPS
/// Default is disabled
pub async fn set_csrf_secure_cookie_enable(secure: bool) {
    let mut w = SECURE_COOKIE.write().await;
    *w = secure;
}

/// Set the signing key for csrf token. 
/// If not called, CSRF token will be signed by a random 32 char alphanumeric string.
/// Recommend to set a key with at least 32 characters.
/// Better to call before your server start. Otherwise some existing CSRF token will become invalid.
pub async fn set_csrf_token_sign_key(key:&str) {
    let mut w = KEY.write().await;
    *w = key.into();
}

/// Sign a message with the previously set sign key.
/// Used internally, but you could use it elsewhere too.
/// Return hex encoded signed message
pub async fn sign_message(message: &str) -> String {
    // Create HMAC instance
    let r = KEY.read().await;
    let key = r.clone();
    drop(r);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let bytes = mac.finalize().into_bytes();
    // Sign the message
    return encode(bytes);
}

/// Generate a CSRF token in format of xxxx-yyyy
/// xxxx is the short uuid generated using uuid-short.
/// yyyy is the hmac signature of the uuid-short signed with the sign key set previously 
/// (or default 32 char random key if not set)
pub async fn generate_csrf_token() -> String {
    let result = short!();
    let token_raw = result.to_string();
    return format!("{}-{}", token_raw, sign_message(&token_raw).await);
}

/// Given a CSRF key of xxx-yyy format, use the previously set sign key to validate the value.
/// Return true if the token is valid and signature matches
pub async fn validate_csrf_token(what:&str) -> bool {
    let mut tokens = what.splitn(2, '-');
    if let(Some(first), Some(second)) = (tokens.next(), tokens.next()) {
        return sign_message(first).await == second;
    }
    return false;
}

/// This is a verification function for sign_message. You can give input text, and a signature.
/// The code will in computed signature to match the signature and return true if signature maches.
pub async fn verify_signature(message: &str, signature: &str) -> bool {
    let computed_signature = sign_message(message).await;
    computed_signature == signature
}

/// Represents a CSRFToken. You can use request extension to get it.
/// If you enable CSRF protection, the extension will guarantee the CSRF token is either
///    Freshly initialized and cookie is set
///    Or cookie seen, cookie value is valid, so we reuse the cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CSRFToken{ 
    pub token:String,
    pub is_new:bool,
}

/// Represents a CSRFToken from x-csrf-token request header. If it is available, it will be availabe for you
/// to use using the auto extractor. 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CSRFTokenFromRequest(String);

impl<B> OptionalFromRequestParts<B> for CSRFTokenFromRequest 
    where B:Send + Sync
{
    type Rejection = Infallible;
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &B,
    ) -> Result<Option<Self>, Self::Rejection> {
        let val = parts.headers.get("x-csrf-token").map(|x| x.to_str().ok()).flatten();
        match val {
            None => {
                return Ok(None)
            },
            Some(inner) => {
                let token = inner.to_string();
                if token.len() > 0 && validate_csrf_token(&token).await {
                    return Ok(Some(CSRFTokenFromRequest(token)));
                } else {
                    return Ok(None);
                }
            }
        }
    }
}

/// A handler for you to expose to client. You should expose to client using your router.
pub async fn get_csrf_token(request:Request) -> Result<Json<CSRFToken>, impl IntoResponse> {
    let token1:Option<&CSRFToken> = request.extensions().get();
    match token1 {
        None => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "This request did not enable csrf_protection middleware"));
        },
        Some(token) => {
            return Ok(Json(token.clone()));
        }
    }
}

fn get_csrf_token_from_query(request:&Request) -> Option<String> {
    let uri: &Uri = request.uri();

    if let Some(query) = uri.query() {
        let params: HashMap<String, String> = serde_urlencoded::from_str(query).unwrap_or_default();
        
        if let Some(value) = params.get("csrf_token") {
            return Some(value.clone())
        }
    }
    None
}

/// Middleware to protect CSRF
/// ```rust,no_run
/// use axum_csrf_simple as csrf;
/// use axum::middleware;
/// use axum::routing::get;
/// use axum::Router;
/// use std::net::SocketAddr;
/// 
/// #[tokio::main]
/// async fn main() {
///   csrf::set_csrf_token_sign_key("key").await;
///   csrf::set_csrf_secure_cookie_enable(false).await;
///   let app1 = Router::new()
///      .route("/admin/endpoint1", get(handle1).post(handle1).put(handle1))
///      .route("/api/csrf", get(csrf::get_csrf_token))
///      .route_layer(middleware::from_fn(csrf::csrf_protect));
///   let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
///   axum_server::bind(addr)
///     .serve(app1.into_make_service())
///     .await
///     .unwrap();
/// }
/// 
/// async fn handle1() -> &'static str{
///     "HELLO"
/// }
/// ```
pub async fn csrf_protect(mut request: Request, next: Next) -> Result<Response, StatusCode> {
    let csrf_token_from_cookie = request.headers().get(http::header::COOKIE)
        .map(|x| x.to_str().ok()).flatten()
        .map(|x| {
            x.split(";").find(|y| y.starts_with("csrf_token="))
        })
        .flatten()
        .map(|x| x.splitn(2, '='))
        .map(|x| x.last())
        .flatten()
        .map(|x| x.trim())
        .map(|x| x.to_string());
    let need_new_token: bool;
    let actual_token = match csrf_token_from_cookie {
        Some(token) => {
            let is_valid = validate_csrf_token(&token).await;
            if !is_valid {
                need_new_token = true;
                CSRFToken{ token: generate_csrf_token().await, is_new: true}
            } else {
                need_new_token = false;
                CSRFToken{ token, is_new:false}
            }
        },
        None => {
            need_new_token = true;
            CSRFToken{token: generate_csrf_token().await, is_new: true}
        }
    };
    request.extensions_mut().insert(actual_token.clone());
    let actual_token_str = actual_token.clone();
    let csrf_token_from_cookie_str = actual_token.token;
    let csrf_token_from_header_or_query = request.headers()
        .get("x-csrf-token")
        .map(|x| x.to_str()
            .ok()
            .map(|x| x.to_string())
        ).flatten().or(get_csrf_token_from_query(&request));
    //let csrf_token_from_query_string = request
    let method = request.method();
    let mut response = match method {
        &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH => {
            let valid_csrf = match csrf_token_from_header_or_query {
                Some(val) =>  {
                    if val == csrf_token_from_cookie_str {
                        true
                    } else {
                        false
                    }
                },
                _ => false,
            };
            if valid_csrf {
                next.run(request).await
            } else {
                let unauthorized_response:Response<Body> = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("x-reject-reason", "invalid-csrf-token")
                    .body("Unauthorized due to invalid csrf token.".into())
                    .unwrap();
                let response = unauthorized_response;
                response
            }
        },
        _ => {
            next.run(request).await
        }
    };
    if need_new_token {
        // A new CSRF token is genreated, we need to set to cookie
        let token = actual_token_str.token;
        let secure = {
            *SECURE_COOKIE.read().await
        };
        let csrf_cookie = Cookie::build(("csrf_token", token.clone()))
            .http_only(true)
            .secure(secure)
            .same_site(cookie::SameSite::Strict)
            .path("/");
        let header_value = csrf_cookie.build().encoded().to_string();
        response.headers_mut().append(http::header::SET_COOKIE, HeaderValue::from_str(&header_value).unwrap());
    } 
    return Ok(response);
}
