pub mod jwt_producer {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::Value;

    #[derive(Clone)]
    pub struct JwtProducer {
        header: Header,
        encoding_key: EncodingKey,
    }

    impl JwtProducer {
        pub fn noop() -> JwtProducer {
            return JwtProducer {
                header: Header::default(),
                encoding_key: EncodingKey::from_secret("".as_bytes()),
            };
        }

        pub fn from(header: Header, encoding_key: EncodingKey) -> JwtProducer {
            return JwtProducer {
                header,
                encoding_key,
            };
        }

        pub fn encode(&self, claims: &Value) -> String {
            jsonwebtoken::encode(&self.header, claims, &self.encoding_key).unwrap()
        }
    }
}
