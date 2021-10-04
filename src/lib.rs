use crate::jwt::jwt_producer::JwtProducer;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use proxy_wasm::hostcalls::log;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Error;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

mod jwt;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|context_id| -> Box<dyn RootContext> {
        Box::new(AuthRootContext {
            jwt_producer: JwtProducer::noop(),
            introspect_config: IntrospectConfig {
                upstream: String::new(),
                path: String::new(),
                authority: String::new(),
            },
        })
    })
}

// Using "raw" config struct copies
// to decouple configuration to logic
// structs
#[derive(Deserialize)]
struct RawConfig {
    jwt: RawConfigJwt,
    introspect_endpoint: RawConfigIntrospect,
}

#[derive(Deserialize)]
struct RawConfigJwt {
    algorithm_name: String,
    key: String,
    output_header_name: String,
}

#[derive(Deserialize)]
struct RawConfigIntrospect {
    upstream: String,
    path: String,
    authority: String,
}

#[derive(Clone)]
struct IntrospectConfig {
    upstream: String,
    path: String,
    authority: String,
}

struct AuthHttpContext {
    jwt_producer: JwtProducer,
    introspect_config: IntrospectConfig,
}

impl AuthHttpContext {}

impl Context for AuthHttpContext {}

impl HttpContext for AuthHttpContext {}

struct AuthRootContext {
    jwt_producer: JwtProducer,
    introspect_config: IntrospectConfig,
}

impl Context for AuthRootContext {}

impl RootContext for AuthRootContext {
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        true
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let config_bytes = self.get_configuration().unwrap() {
            let cfg: RawConfig = serde_json::from_slice(config_bytes.as_slice()).unwrap();

            {
                let jwt_algorithm_name: Algorithm;
                match Algorithm::from_str(cfg.jwt.algorithm_name.as_str()) {
                    Ok(algorithm) => {
                        jwt_algorithm_name = algorithm;
                    }
                    Err(error) => {
                        log(
                            LogLevel::Error,
                            format!("JWT encoding key error: {:?}", error).as_str(),
                        );
                        return false;
                    }
                }

                let jwt_encoding_key: EncodingKey;
                match EncodingKey::from_rsa_pem(cfg.jwt.key.as_bytes()) {
                    Ok(encoding_key) => {
                        jwt_encoding_key = encoding_key;
                    }
                    Err(error) => {
                        log(
                            LogLevel::Error,
                            format!("JWT encoding key error: {:?}", error).as_str(),
                        );
                        return false;
                    }
                }
                self.jwt_producer =
                    JwtProducer::from(Header::new(jwt_algorithm_name), jwt_encoding_key)
            }
            {
                // TODO validation
                self.introspect_config = IntrospectConfig {
                    upstream: cfg.introspect_endpoint.upstream,
                    path: cfg.introspect_endpoint.path,
                    authority: cfg.introspect_endpoint.authority,
                }
            }
        }
        true
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        let http_context = AuthHttpContext {
            jwt_producer: self.jwt_producer.clone(),
            introspect_config: self.introspect_config.clone(),
        };
        return Some(Box::from(http_context));
    }
}
