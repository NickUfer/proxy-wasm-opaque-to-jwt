# Proxy WASM - Opaque To JWT Auth Token

This is a http proxy filter which converts opaque authorization tokens to signed JWT's
containing claims provided by an OAuth2 token introspection endpoint.
RFC: [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)

## Configuration

An example configuration of the filter.

```json
{
  "introspect_endpoint": {
    "authority": "id.example.com", # Hostname of the endpoint
    "path": "/oauth2/introspect", # Introspection endpoint path
    "upstream": "oauth2-authorization-server" # Under e.g. Envoy Proxy the name of the cluster which provides the endpoint
  },
  "jwt": {
    "key": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKFLhOYO7szSDiGMXNkrNm/n2ofWEGrNNb2l+12id/wf\n-----END PRIVATE KEY-----", # Key to use for jwt signing
    "output_header_name": "X-JWT-User", # Header name to store the JWT in. This header is appended to the incoming request available for upstream services
    "algorithm": "EdDSA" # Algorithm to use for jwt signing
  }
}
```

A full example envoy v3 config can be found in [examples/envoy-minimal.yml](examples/envoy-minimal.yml).

#### Supported Signing Algorithms

|Algorithm|Supported|
|---|---|
|HMAC|
|`HS256`|[X]|
|`HS384`|[X]|
|`HS512`|[X]|
|RSA|
|`RS256`|[X]|
|`RS384`|[X]|
|`RS512`|[X]|
|`PS256`|[X]|
|`PS384`|[X]|
|`PS512`|[X]|
|ECDSA *(support planned)*||
|`ES256`|[]|
|`ES384`|[]|
|`ES512`|[]|
|EdDSA|
|`EdDSA`|[X]|

#### Supported JWT claims

These claims are included in the JWT if provided:

|Claim|Supported|
|---|---|
|`exp`|[X]|
|`iat`|[X]|
|`nbf`|[X]|
|`iss`|[X]|
|`aud` *(as array)*|[X]|
|`jti`|[X]|
|`sub`|[X]|
|`sub`|[X]|


Note: Claims are planned to be completely customizable with [Jsonnet](https://jsonnet.org/).