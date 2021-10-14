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

```json5
{
  "introspect_endpoint": {
    "authority": "id.example.com", // Hostname of the endpoint
    "path": "/oauth2/introspect", // Introspection endpoint path
    "upstream": "oauth2-authorization-server" // Under e.g. Envoy Proxy the name of the cluster which provides the endpoint
  },
  "jwt": {
    "key": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKFLhOYO7szSDiGMXNkrNm/n2ofWEGrNNb2l+12id/wf\n-----END PRIVATE KEY-----", // Key to use for jwt signing
    "output_header_name": "X-JWT-User", // Header name to store the JWT in. This header is appended to the incoming request available for upstream services
    "algorithm": "EdDSA" // Algorithm to use for jwt signing
  }
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

#### Supported JWT claims

These claims are included in the JWT if provided:

|Claim|Supported|
|---|---|
|`exp`|:heavy_check_mark:|
|`iat`|:heavy_check_mark:|
|`nbf`|:heavy_check_mark:|
|`iss`|:heavy_check_mark:|
|`aud` *(as array)*|:heavy_check_mark:|
|`jti`|:heavy_check_mark:|
|`sub`|:heavy_check_mark:|
|`sub`|:heavy_check_mark:|


Note: Claims are planned to be completely customizable with [Jsonnet](https://jsonnet.org/), even custom claims provided by the introspection endpoint.
