package envoy.authz

import future.keywords
import input.attributes.request.http

default allow := false

allow if {
	no_authz_path
}

allow if {
	r := token.payload.role
	r in is_allowed_permission
}

no_authz_path if {
	http.method == "GET"
	http.path == "/healthz"
}

no_authz_path if {
	http.method == "POST"
	http.path == "/auth/login"
}

is_allowed_permission contains role if {
	role_permissions := {
		"guest": [{"method": "GET", "path": "/something"}],
		"admin": [
			{"method": "POST", "path": "/create"},
			{"method": "GET", "path": "/list"},
			{"method": "POST", "path": "/something"},
		],
	}

	some permission in role_permissions[role]
	http.method == permission.method
	http.path == permission.path
}

token := {"payload": payload} if {
	[_, jwt] := split(http.headers.authorization, " ")
	[_, payload, _] := io.jwt.decode(jwt)
}
