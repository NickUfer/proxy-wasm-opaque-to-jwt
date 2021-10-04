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

impl RootContext for AuthRootContext {}
