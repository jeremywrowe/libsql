use crate::auth::{Authenticated, Authorized, Permission, AuthError, HttpAuthHeader};
use crate::auth::constants::GRPC_AUTH_HEADER;
use crate::namespace::NamespaceName;

use anyhow::Result;
use axum::headers::HeaderValue;
use tonic::Status;

/// Authentication that is required to access the server.
#[derive(Default)]
pub struct AuthType {
    /// When true, no authentication is required.
    pub disabled: bool,
    /// If `Some`, we accept HTTP basic auth if it matches this value.
    pub http_basic: Option<String>,
    /// If `Some`, we accept all JWTs signed by this key.
    pub jwt_key: Option<jsonwebtoken::DecodingKey>,
}

impl AuthType {
    pub fn authenticate_http(
        &self,
        auth_header: Option<&hyper::header::HeaderValue>,
        disable_namespaces: bool,
        namespace_jwt_key: Option<jsonwebtoken::DecodingKey>,
    ) -> Result<Authenticated, AuthError> {
        if self.disabled {
            return Ok(Authenticated::Authorized(Authorized {
                namespace: None,
                permission: Permission::FullAccess,
            }));
        }

        let Some(auth_header) = auth_header else {
            return Err(AuthError::HttpAuthHeaderMissing);
        };

        match parse_http_auth_header(auth_header)? {
            HttpAuthHeader::Basic(actual_value) => {
                let Some(expected_value) = self.http_basic.as_ref() else {
                    return Err(AuthError::BasicNotAllowed);
                };
                // NOTE: this naive comparison may leak information about the `expected_value`
                // using a timing attack
                let actual_value = actual_value.trim_end_matches('=');
                let expected_value = expected_value.trim_end_matches('=');
                if actual_value == expected_value {
                    Ok(Authenticated::Authorized(Authorized {
                        namespace: None,
                        permission: Permission::FullAccess,
                    }))
                } else {
                    Err(AuthError::BasicRejected)
                }
            }
            HttpAuthHeader::Bearer(token) => {
                self.validate_jwt(&token, disable_namespaces, namespace_jwt_key)
            }
        }
    }

    pub fn authenticate_grpc<T>(
        &self,
        req: &tonic::Request<T>,
        disable_namespaces: bool,
        namespace_jwt_key: Option<jsonwebtoken::DecodingKey>,
    ) -> Result<Authenticated, Status> {
        let metadata = req.metadata();

        let auth = metadata
            .get(GRPC_AUTH_HEADER)
            .map(|v| v.to_bytes().expect("Auth should always be ASCII"))
            .map(|v| HeaderValue::from_maybe_shared(v).expect("Should already be valid header"));

        self.authenticate_http(auth.as_ref(), disable_namespaces, namespace_jwt_key)
            .map_err(Into::into)
    }

    pub fn authenticate_jwt(
        &self,
        jwt: Option<&str>,
        disable_namespaces: bool,
        namespace_jwt_key: Option<jsonwebtoken::DecodingKey>,
    ) -> Result<Authenticated, AuthError> {
        if self.disabled {
            return Ok(Authenticated::Authorized(Authorized {
                namespace: None,
                permission: Permission::FullAccess,
            }));
        }

        let Some(jwt) = jwt else {
            return Err(AuthError::JwtMissing);
        };

        self.validate_jwt(jwt, disable_namespaces, namespace_jwt_key)
    }

    fn validate_jwt(
        &self,
        jwt: &str,
        disable_namespaces: bool,
        namespace_jwt_key: Option<jsonwebtoken::DecodingKey>,
    ) -> Result<Authenticated, AuthError> {
        let jwt_key = match namespace_jwt_key.as_ref() {
            Some(jwt_key) => jwt_key,
            None => match self.jwt_key.as_ref() {
                Some(jwt_key) => jwt_key,
                None => return Err(AuthError::JwtNotAllowed),
            },
        };
        validate_jwt(jwt_key, jwt, disable_namespaces)
    }
}

fn parse_http_auth_header(
    header: &hyper::header::HeaderValue,
) -> Result<HttpAuthHeader, AuthError> {
    let Ok(header) = header.to_str() else {
        return Err(AuthError::HttpAuthHeaderInvalid);
    };

    let Some((scheme, param)) = header.split_once(' ') else {
        return Err(AuthError::HttpAuthHeaderInvalid);
    };

    if scheme.eq_ignore_ascii_case("basic") {
        Ok(HttpAuthHeader::Basic(param.into()))
    } else if scheme.eq_ignore_ascii_case("bearer") {
        Ok(HttpAuthHeader::Bearer(param.into()))
    } else {
        Err(AuthError::HttpAuthHeaderUnsupportedScheme)
    }
}

fn validate_jwt(
    jwt_key: &jsonwebtoken::DecodingKey,
    jwt: &str,
    disable_namespace: bool,
) -> Result<Authenticated, AuthError> {
    use jsonwebtoken::errors::ErrorKind;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.required_spec_claims.remove("exp");

    match jsonwebtoken::decode::<serde_json::Value>(jwt, jwt_key, &validation).map(|t| t.claims) {
        Ok(serde_json::Value::Object(claims)) => {
            tracing::trace!("Claims: {claims:#?}");
            let namespace = if disable_namespace {
                None
            } else {
                claims
                    .get("id")
                    .and_then(|ns| NamespaceName::from_string(ns.as_str()?.into()).ok())
            };

            let permission = match claims.get("a").and_then(|s| s.as_str()) {
                Some("ro") => Permission::ReadOnly,
                Some("rw") => Permission::FullAccess,
                Some(_) => return Ok(Authenticated::Anonymous),
                // Backward compatibility - no access claim means full access
                None => Permission::FullAccess,
            };

            Ok(Authenticated::Authorized(Authorized {
                namespace,
                permission,
            }))
        }
        Ok(_) => Err(AuthError::JwtInvalid),
        Err(error) => Err(match error.kind() {
            ErrorKind::InvalidToken
            | ErrorKind::InvalidSignature
            | ErrorKind::InvalidAlgorithm
            | ErrorKind::Base64(_)
            | ErrorKind::Json(_)
            | ErrorKind::Utf8(_) => AuthError::JwtInvalid,
            ErrorKind::ExpiredSignature => AuthError::JwtExpired,
            ErrorKind::ImmatureSignature => AuthError::JwtImmature,
            _ => AuthError::Other,
        }),
    }
}
