package envoy.authz

import future.keywords
import input.attributes.request.http.headers
import input.parsed_path

default allow := false

allow if {
	no_authz_rpc
}

allow if {
	r := token.payload.role
	r in is_allowed_permission
}

no_authz_rpc if {
	no_auth_rpc := {
		"grpc.reflection.v1alpha.ServerReflection": ["ServerReflectionInfo"],
		"auth.v1.AuthService": ["Signin"],
	}
	some rpcs in no_auth_rpc[parsed_path[0]]
	parsed_path[1] == rpcs
}

is_allowed_permission contains role if {
	role_permission := {
		"admin": [
			{"service": "misc.v1.MiscService", "rpc": "Create"},
			{"service": "misc.v1.MiscService", "rpc": "List"},
		],
		"guest": [{"service": "misc.v1.MiscService", "rpc": "List"}],
	}

	some p in role_permission[role]
	parsed_path[0] == p.service
	parsed_path[1] == p.rpc
}

token := {"payload": payload} if {
	[_, jwt] := split(headers.authorization, " ")
	[_, payload, _] := io.jwt.decode(jwt)
}
