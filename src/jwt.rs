pub mod jwt_producer {
    use dyn_clone::DynClone;
    use jwt_simple::algorithms::*;
    use jwt_simple::claims::Audiences::AsSet;
    use jwt_simple::prelude::*;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::str::FromStr;

    #[derive(Clone)]
    pub struct JwtProducer {
        key_pair: Option<Box<dyn Encoder>>,
    }

    impl JwtProducer {
        pub fn noop() -> JwtProducer {
            JwtProducer {
                key_pair: Option::Some(Box::new(NoopEncoder {})),
            }
        }

        pub fn from(algorithm: Algorithm, key: String) -> JwtProducer {
            let key_pair: Box<dyn Encoder> = match algorithm {
                Algorithm::RS256 => Box::new(RS256KeyPair::from_pem(key.as_str()).unwrap()),
                Algorithm::HS256 => Box::new(HS256Key::from_bytes(key.as_bytes())),
                Algorithm::HS384 => Box::new(HS384Key::from_bytes(key.as_bytes())),
                Algorithm::HS512 => Box::new(HS512Key::from_bytes(key.as_bytes())),
                Algorithm::RS384 => Box::new(RS384KeyPair::from_pem(key.as_str()).unwrap()),
                Algorithm::RS512 => Box::new(RS512KeyPair::from_pem(key.as_str()).unwrap()),
                Algorithm::PS256 => Box::new(PS256KeyPair::from_pem(key.as_str()).unwrap()),
                Algorithm::PS384 => Box::new(PS384KeyPair::from_pem(key.as_str()).unwrap()),
                Algorithm::PS512 => Box::new(PS512KeyPair::from_pem(key.as_str()).unwrap()),
                Algorithm::EdDSA => Box::new(Ed25519KeyPair::from_pem(key.as_str()).unwrap()),
                _ => Box::new(NoopEncoder {}),
            };
            return JwtProducer {
                key_pair: Option::Some(key_pair),
            };
        }

        pub fn encode_jwt(&self, claims: Value) -> String {
            self.key_pair.as_ref().unwrap().encode_jwt(claims)
        }
    }

    pub trait Encoder: DynClone {
        fn encode_jwt(&self, claims: Value) -> String; // TODO refactor to return Result
    }

    dyn_clone::clone_trait_object!(Encoder);

    #[derive(Clone)]
    struct NoopEncoder {}

    impl Encoder for NoopEncoder {
        fn encode_jwt(&self, _: Value) -> String {
            String::from("NoopEncoder") // FIXME error
        }
    }

    impl Encoder for RS512KeyPair {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.sign(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for RS384KeyPair {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.sign(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for RS256KeyPair {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.sign(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for PS512KeyPair {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.sign(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for PS384KeyPair {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.sign(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for PS256KeyPair {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.sign(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for HS256Key {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.authenticate(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for HS384Key {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.authenticate(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for HS512Key {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.authenticate(convert_value_to_claims(claims)).unwrap();
        }
    }

    impl Encoder for Ed25519KeyPair {
        fn encode_jwt(&self, claims: Value) -> String {
            return self.sign(convert_value_to_claims(claims)).unwrap();
        }
    }

    fn convert_value_to_claims(value: Value) -> JWTClaims<NoCustomClaims> {
        let mut audiences = HashSet::new();
        for audience in value.get("aud").unwrap().as_array().unwrap() {
            audiences.insert(String::from(audience.as_str().unwrap()));
        }
        return JWTClaims {
            issued_at: Option::Some(UnixTimeStamp::from_secs(
                value.get("iat").unwrap().as_u64().unwrap(),
            )),
            expires_at: Option::Some(UnixTimeStamp::from_secs(
                value.get("exp").unwrap().as_u64().unwrap(),
            )),
            invalid_before: Option::Some(UnixTimeStamp::from_secs(
                value.get("nbf").unwrap().as_u64().unwrap(),
            )),
            audiences: Option::Some(AsSet(audiences)),
            issuer: Option::Some(String::from(value.get("iss").unwrap().as_str().unwrap())),
            jwt_id: None,
            subject: Option::Some(String::from(value.get("sub").unwrap().as_str().unwrap())),
            nonce: None,
            custom: NoCustomClaims {},
        };
    }

    // The MIT License (MIT)
    //
    // Copyright (c) 2015 Vincent Prouillet
    //
    // Permission is hereby granted, free of charge, to any person obtaining a copy
    // of this software and associated documentation files (the "Software"), to deal
    // in the Software without restriction, including without limitation the rights
    // to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    // copies of the Software, and to permit persons to whom the Software is
    // furnished to do so, subject to the following conditions:
    //
    // The above copyright notice and this permission notice shall be included in all
    // copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    // OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    // SOFTWARE.
    /// The algorithms supported for signing/verifying JWTs
    #[derive(Debug, PartialEq, Hash, Copy, Clone, Serialize, Deserialize)]
    pub enum Algorithm {
        /// HMAC using SHA-256
        HS256,
        /// HMAC using SHA-384
        HS384,
        /// HMAC using SHA-512
        HS512,

        /// ECDSA using SHA-256
        ES256,
        /// ECDSA using SHA-384
        ES384,

        /// RSASSA-PKCS1-v1_5 using SHA-256
        RS256,
        /// RSASSA-PKCS1-v1_5 using SHA-384
        RS384,
        /// RSASSA-PKCS1-v1_5 using SHA-512
        RS512,

        /// RSASSA-PSS using SHA-256
        PS256,
        /// RSASSA-PSS using SHA-384
        PS384,
        /// RSASSA-PSS using SHA-512
        PS512,

        /// Edwards-curve Digital Signature Algorithm (EdDSA)
        EdDSA,
    }

    impl FromStr for Algorithm {
        type Err = String;

        fn from_str(s: &str) -> Result<Algorithm, String> {
            match s.to_uppercase().as_str() {
                "HS256" => Ok(Algorithm::HS256),
                "HS384" => Ok(Algorithm::HS384),
                "HS512" => Ok(Algorithm::HS512),
                "ES256" => Ok(Algorithm::ES256),
                "ES384" => Ok(Algorithm::ES384),
                "RS256" => Ok(Algorithm::RS256),
                "RS384" => Ok(Algorithm::RS384),
                "PS256" => Ok(Algorithm::PS256),
                "PS384" => Ok(Algorithm::PS384),
                "PS512" => Ok(Algorithm::PS512),
                "RS512" => Ok(Algorithm::RS512),
                "EDDSA" => Ok(Algorithm::EdDSA),
                _ => Err(String::from("Algorithm invalid")),
            }
        }
    }
}
