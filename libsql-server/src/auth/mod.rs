pub mod auth_type;
pub mod authenticated;
pub mod authorized;
pub mod constants;
pub mod errors;
pub mod parsers;
pub mod permission;
mod header;

pub use auth_type::*;
pub use authenticated::*;
pub use authorized::*;
pub use constants::*;
pub use errors::*;
pub use parsers::*;
pub use permission::*;
use header::*;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn authenticate_http(auth: &AuthType, header: &str) -> Result<Authenticated, AuthError> {
        auth.authenticate_http(Some(&HeaderValue::from_str(header).unwrap()), false, None)
    }

    const VALID_JWT_KEY: &str = "zaMv-aFGmB7PXkjM4IrMdF6B5zCYEiEGXW3RgMjNAtc";
    const VALID_JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.\
        eyJleHAiOjc5ODg0ODM4Mjd9.\
        MatB2aLnPFusagqH2RMoVExP37o2GFLmaJbmd52OdLtAehRNeqeJZPrefP1t2GBFidApUTLlaBRL6poKq_s3CQ";
    const VALID_READONLY_JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.\
        eyJleHAiOjc5ODg0ODM4MjcsImEiOiJybyJ9.\
        _2ZZiO2HC8b3CbCHSCufXXBmwpl-dLCv5O9Owvpy7LZ9aiQhXODpgV-iCdTsLQJ5FVanWhfn3FtJSnmWHn25DQ";

    macro_rules! assert_ok {
        ($e:expr) => {
            let res = $e;
            if let Err(err) = res {
                panic!("Expected Ok, got Err({:?})", err)
            }
        };
    }

    macro_rules! assert_err {
        ($e:expr) => {
            let res = $e;
            if let Ok(ok) = res {
                panic!("Expected Err, got Ok({:?})", ok);
            }
        };
    }

    #[test]
    fn test_default() {
        let auth = AuthType::default();
        assert_err!(auth.authenticate_http(None, false, None));
        assert_err!(authenticate_http(&auth, "Basic d29qdGVrOnRoZWJlYXI="));
        assert_err!(auth.authenticate_jwt(Some(VALID_JWT), false, None));
    }

    #[test]
    fn test_http_basic() {
        let auth = AuthType {
            http_basic: parse_http_basic_auth_arg("basic:d29qdGVrOnRoZWJlYXI=").unwrap(),
            ..AuthType::default()
        };
        assert_ok!(authenticate_http(&auth, "Basic d29qdGVrOnRoZWJlYXI="));
        assert_ok!(authenticate_http(&auth, "Basic d29qdGVrOnRoZWJlYXI"));
        assert_ok!(authenticate_http(&auth, "Basic d29qdGVrOnRoZWJlYXI==="));

        assert_ok!(authenticate_http(&auth, "basic d29qdGVrOnRoZWJlYXI="));

        assert_err!(authenticate_http(&auth, "Basic d29qdgvronrozwjlyxi="));
        assert_err!(authenticate_http(&auth, "Basic d29qdGVrOnRoZWZveA=="));

        assert_err!(auth.authenticate_http(None, false, None));
        assert_err!(authenticate_http(&auth, ""));
        assert_err!(authenticate_http(&auth, "foobar"));
        assert_err!(authenticate_http(&auth, "foo bar"));
        assert_err!(authenticate_http(&auth, "basic #$%^"));
    }

    #[test]
    fn test_http_bearer() {
        let auth = AuthType {
            jwt_key: Some(parse_jwt_key(VALID_JWT_KEY).unwrap()),
            ..AuthType::default()
        };
        assert_ok!(authenticate_http(&auth, &format!("Bearer {VALID_JWT}")));
        assert_ok!(authenticate_http(&auth, &format!("bearer {VALID_JWT}")));

        assert_err!(authenticate_http(&auth, "Bearer foobar"));
        assert_err!(authenticate_http(
            &auth,
            &format!("Bearer {}", &VALID_JWT[..80])
        ));

        assert_eq!(
            authenticate_http(&auth, &format!("Bearer {VALID_READONLY_JWT}")).unwrap(),
            Authenticated::Authorized(Authorized {
                namespace: None,
                permission: Permission::ReadOnly
            })
        );
    }

    #[test]
    fn test_jwt() {
        let auth = AuthType {
            jwt_key: Some(parse_jwt_key(VALID_JWT_KEY).unwrap()),
            ..AuthType::default()
        };
        assert_ok!(auth.authenticate_jwt(Some(VALID_JWT), false, None));
        assert_err!(auth.authenticate_jwt(Some(&VALID_JWT[..80]), false, None));
    }
}
