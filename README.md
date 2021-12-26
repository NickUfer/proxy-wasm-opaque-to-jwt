# Proxy WASM - Opaque To JWT Auth Token

This is a http proxy filter which converts opaque authorization tokens to signed JWT's
containing claims provided by an OAuth2 token introspection endpoint.
RFC: [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)

## Build From Source

Run make in the project root:
```shell
make build
```
The built wasm file should be located at `target/wasm32-wasi/release/proxy_wasm_opaque_to_jwt.wasm`.

## Configuration

An example configuration of the filter.

```yaml
introspect_endpoint:
  authority: "id.example.com" # Hostname of the endpoint
  path: "/oauth2/introspect" # Introspection endpoint path
  upstream: "oauth2-authorization-serve" # Under e.g. Envoy Proxy the name of the cluster which provides the endpoint
jwt:
  key: '' # Key to use for jwt signing. Generate new key with command "openssl genpkey -algorithm ed25519"
  output_header_name: "X-JWT-User" # Header name to store the JWT in. This header is appended to the incoming request available for upstream services
  algorithm: "EdDSA" # Algorithm to use for jwt signing
  jsonnet_template: |- # Jsonnet function to use for transforming the introspection data to jwt claims
    function(introspect_json) {
      // If expiration is not set, set it to 0 to make it invalid
      exp: if(std.objectHas(introspect_json, "exp")) then introspect_json.exp else 0,
      iat: if(std.objectHas(introspect_json, "iat")) then introspect_json.iat,
      nbf: if(std.objectHas(introspect_json, "nbf")) then introspect_json.nbf,
      iss: if(std.objectHas(introspect_json, "iss")) then introspect_json.iss,
      // If supplied aud is not an array convert it to one with 1 element.
      aud: if(std.objectHas(introspect_json, "aud")) then (if(std.isArray(introspect_json.aud)) then introspect_json.aud else [introspect_json.aud]),
      jti: if(std.objectHas(introspect_json, "jti")) then introspect_json.jti,
      sub: if(std.objectHas(introspect_json, "sub")) then introspect_json.sub
    }
```

A full example envoy v3 config can be found in [examples/envoy-minimal.yml](examples/envoy-minimal.yml).

#### Supported Signing Algorithms

|Algorithm|Supported|
|---|---|
|HMAC|
|`HS256`|:heavy_check_mark:|
|`HS384`|:heavy_check_mark:|
|`HS512`|:heavy_check_mark:|
|RSA|
|`RS256`|:heavy_check_mark:|
|`RS384`|:heavy_check_mark:|
|`RS512`|:heavy_check_mark:|
|`PS256`|:heavy_check_mark:|
|`PS384`|:heavy_check_mark:|
|`PS512`|:heavy_check_mark:|
|ECDSA *(support planned)*||
|`ES256`|:construction:|
|`ES384`|:construction:|
|`ES512`|:construction:|
|EdDSA|
|`EdDSA`|:heavy_check_mark:|

#### JWT claims

These claims are included in the JWT by default if provided:

|Claim|Supported|
|---|---|
|`exp`|:heavy_check_mark:|
|`iat`|:heavy_check_mark:|
|`nbf`|:heavy_check_mark:|
|`iss`|:heavy_check_mark:|
|`aud` *(as array)*|:heavy_check_mark:|
|`jti`|:heavy_check_mark:|
|`sub`|:heavy_check_mark:|

##### Change the JWT claims

With [Jsonnet](https://jsonnet.org/) you are able to include custom claims
or synthesize new ones or add static claims.

The default claims already use a [jsonnet template](src/default.jsonnet) to construct the JWT token.
With help from [jsonnet.org](https://jsonnet.org/learning/tutorial.html) and the default template
you should be able to change the generated JWT to your requirements.

This filter uses [Top-Level Arguments](https://jsonnet.org/learning/tutorial.html#parameterize-entire-config).
Basically the filter needs a function which generates the jwt claims. It is called with the introspection json as a parameter.
In the function you can add all claims you want to add to your jwt token. An example can be found at [src/default.jsonnet](src/default.jsonnet).
```jsonnet
function(introspect_json) {
  // ... put your claims inside here
}
```
