use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;

use crate::jwt::VerifiedToken;

pub struct VerifiedAAuthToken(pub VerifiedToken);

impl<S> FromRequestParts<S> for VerifiedAAuthToken
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<VerifiedToken>()
            .cloned()
            .map(VerifiedAAuthToken)
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Missing verified AAuth token".into(),
            ))
    }
}
