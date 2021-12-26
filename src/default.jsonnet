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
