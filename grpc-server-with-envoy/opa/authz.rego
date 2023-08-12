package envoy.authz

import future.keywords
import input.parsed_path

default allow := false

allow if {
	parsed_path[0] == "grpc.reflection.v1alpha.ServerReflection"
	parsed_path[1] == "ServerReflectionInfo"
}

allow if {
	is_allowd_rpc
}

is_allowd_rpc if {
	permission_rpcs := {
		"auth.v1.AuthService": ["Signin"],
		"misc.v1.MiscService": ["Create", "List"],
	}
	some rpcs in permission_rpcs[parsed_path[0]]
	parsed_path[1] == rpcs
}
