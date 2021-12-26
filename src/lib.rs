use crate::jwt::jwt_producer::{Algorithm, AnyCustomClaims, JwtProducer};
use jrsonnet_evaluator::error::LocError;
use jrsonnet_evaluator::Val;
use jwt_simple::claims::JWTClaims;
use proxy_wasm::hostcalls::log;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde_derive::Deserialize;
use serde_json::Value;
use std::str::FromStr;
use std::string::FromUtf8Error;
use std::time::Duration;

mod jsonnet;
mod jwt;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace); // TODO make configurable
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(AuthRootContext {
            jwt_header_name: String::new(),
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
    algorithm: String,
    key: String,
    output_header_name: String,
    jsonnet_template: String,
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
    jwt_header_name: String,
    jwt_producer: JwtProducer,
    introspect_config: IntrospectConfig,
}

impl AuthHttpContext {
    fn introspect_token(&mut self, token: &str) -> Result<u32, Status> {
        let body = vec![("token", token)];
        let encoded_body = serde_urlencoded::to_string(body).unwrap();

        return self.dispatch_http_call(
            self.introspect_config.upstream.as_str(),
            vec![
                (":method", "POST"),
                (":path", self.introspect_config.path.as_str()),
                (":authority", self.introspect_config.authority.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Option::Some(encoded_body.into_bytes().as_slice()),
            vec![],
            Duration::from_millis(200),
        );
    }
}

impl Context for AuthHttpContext {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        match self.get_http_call_response_body(0, body_size) {
            None => {
                self.resume_http_request();
            }
            Some(response_bytes) => {
                // Check if token is still active
                match serde_json::from_slice::<Value>(response_bytes.as_slice()) {
                    Ok(value) => {
                        if !value.get("active").unwrap().as_bool().unwrap() {
                            self.resume_http_request();
                            return;
                        }
                    }
                    Err(e) => {
                        log(
                            LogLevel::Error,
                            format!(
                                "Could not read introspection endpoint response body: {:?}",
                                e
                            )
                            .as_str(),
                        );
                        self.resume_http_request();
                        return;
                    }
                };

                let body = match String::from_utf8(response_bytes) {
                    Ok(body) => body,
                    Err(e) => {
                        log(
                            LogLevel::Error,
                            format!(
                                "Could not read introspection endpoint response body: {:?}",
                                e
                            )
                            .as_str(),
                        );
                        self.resume_http_request();
                        return;
                    }
                };

                let rendered_jsonnet = match self.jwt_producer.render_jsonnet(body) {
                    Ok(json_string) => json_string,
                    Err(e) => {
                        log(
                            LogLevel::Error,
                            format!(
                                "Could not apply introspection endpoint response to jsonnet: {:?}",
                                e
                            )
                            .as_str(),
                        );
                        self.resume_http_request();
                        return;
                    }
                };

                let jwt_claims = match serde_json::from_str::<JWTClaims<AnyCustomClaims>>(
                    rendered_jsonnet.as_str(),
                ) {
                    Ok(value) => value,
                    Err(e) => {
                        log(
                            LogLevel::Error,
                            format!("Could not parse jwt claims from string: {:?}", e).as_str(),
                        );
                        self.resume_http_request();
                        return;
                    }
                };

                self.add_http_request_header(
                    self.jwt_header_name.as_str(),
                    self.jwt_producer.encode_jwt(jwt_claims).as_str(),
                );
                self.resume_http_request();
            }
        }
    }
}

impl HttpContext for AuthHttpContext {
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        let token: String;
        match self.get_http_request_header("authorization") {
            Some(auth_header) => {
                if !auth_header.starts_with("Bearer ") {
                    log(
                        LogLevel::Debug,
                        format!(
                            "Authorization header not a Bearer token, skipping. Header: {}",
                            auth_header
                        )
                        .as_str(),
                    );
                    return Action::Continue;
                }
                // Removes Bearer from header to get actual token
                // Expects there are no more spaces
                token = String::from(&auth_header[7..auth_header.len()]);
            }
            _ => return Action::Continue, // No header, skip auth any further processing
        }

        return match self.introspect_token(token.as_str()) {
            Ok(_) => Action::Pause,
            Err(error) => {
                log(
                    LogLevel::Error,
                    format!("Error while calling introspect endpoint: {:?}", error).as_str(),
                );
                Action::Continue
            }
        };
    }
}

struct AuthRootContext {
    jwt_header_name: String,
    jwt_producer: JwtProducer,
    introspect_config: IntrospectConfig,
}

impl Context for AuthRootContext {}

impl RootContext for AuthRootContext {
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        true
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        match self.get_configuration() {
            Some(config_bytes) => {
                let cfg: RawConfig = serde_yaml::from_slice(config_bytes.as_slice()).unwrap();
                if !cfg.jwt.output_header_name.is_empty() {
                    self.jwt_header_name = cfg.jwt.output_header_name;
                } else {
                    self.jwt_header_name = String::from("x-jwt-user");
                }

                {
                    let jwt_algorithm: Algorithm;
                    match Algorithm::from_str(cfg.jwt.algorithm.as_str()) {
                        Ok(algorithm) => {
                            jwt_algorithm = algorithm;
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
                        JwtProducer::from(jwt_algorithm, cfg.jwt.key, cfg.jwt.jsonnet_template);
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
            None => {
                log(
                    LogLevel::Error,
                    "Failed to read non existent configuration.",
                );
            }
        }
        true
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        let http_context = AuthHttpContext {
            jwt_header_name: self.jwt_header_name.clone(),
            jwt_producer: self.jwt_producer.clone(),
            introspect_config: self.introspect_config.clone(),
        };
        return Some(Box::from(http_context));
    }

    fn get_type(&self) -> Option<ContextType> {
        Option::Some(ContextType::HttpContext)
    }
}
