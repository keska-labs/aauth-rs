use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;

use aauth::jwt::ParsedToken;

pub struct VerifiedAAuthToken(pub ParsedToken);

impl<S> FromRequestParts<S> for VerifiedAAuthToken
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ParsedToken>()
            .cloned()
            .map(VerifiedAAuthToken)
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Missing verified AAuth token".into(),
            ))
    }
}
