package envoy.authz

import future.keywords
import input.attributes.request.http

default allow := false

allow if {
	no_authz_path
}

allow if {
	action_allowed
}

no_authz_path if {
	http.method == "GET"
	http.path == "/healthz"
}

no_authz_path if {
	http.method == "POST"
	http.path == "/auth/login"
}

action_allowed if {
	http.method == "POST"
	glob.match("/create", ["/"], http.path)
	is_admin
}

action_allowed if {
	http.method == "GET"
	glob.match("/list", ["/"], http.path)
	is_admin
}

action_allowed if {
	http.method == "POST"
	glob.match("/something", ["/"], http.path)
	is_admin
}

action_allowed if {
	http.method == "GET"
	glob.match("/something", ["/"], http.path)
	is_guest
}

token := {"payload": payload} if {
	[_, jwt] := split(http.headers.authorization, " ")
	[_, payload, _] := io.jwt.decode(jwt)
}

default is_admin := false

is_admin if {
	token.payload.role == "admin"
}

default is_guest := false

is_guest if {
	token.payload.role == "guest"
}
