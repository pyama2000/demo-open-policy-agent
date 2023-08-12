package envoy.authz

test_allow {
	not _test_no_authz_rpc
	not _test_is_allowed_permission
}

_test_no_authz_rpc {
	tests := [
		{
			"title": "no auth for reflection",
			"input": {"parsed_path": ["grpc.reflection.v1alpha.ServerReflection", "ServerReflectionInfo"]},
			"expected": true,
		},
		{
			"title": "no auth for signin",
			"input": {"parsed_path": ["auth.v1.AuthService", "Signin"]},
			"expected": true,
		},
	]

	t := tests[_]
	actual := allow with input as t.input
	actual != t.expected
	print(sprintf("failed test '%s'. expected %v, but got %v", [t.title, t.expected, actual]))
}

_test_is_allowed_permission {
	admin_auth := "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.RUEndDEYvTTkstJM_EA3sd9f_Eukdid6hi1HwxtFXKc"
	guest_auth := "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiZ3Vlc3QifQ.VUtSU2es2oeHAtfjYgaOfXeDKOYTUZ-GtRDE3pa5Acc"
	tests := [
		{
			"title": "only admin role can create",
			"input": {
				"attributes": {"request": {"http": {"headers": {"authorization": admin_auth}}}},
				"parsed_path": [
					"misc.v1.MiscService",
					"Create",
				],
			},
			"expected": true,
		},
		{
			"title": "admin role can list",
			"input": {
				"attributes": {"request": {"http": {"headers": {"authorization": admin_auth}}}},
				"parsed_path": [
					"misc.v1.MiscService",
					"List",
				],
			},
			"expected": true,
		},
		{
			"title": "guest role can list",
			"input": {
				"attributes": {"request": {"http": {"headers": {"authorization": guest_auth}}}},
				"parsed_path": [
					"misc.v1.MiscService",
					"List",
				],
			},
			"expected": true,
		},
		{
			"title": "guest role can create",
			"input": {
				"attributes": {"request": {"http": {"headers": {"authorization": guest_auth}}}},
				"parsed_path": [
					"misc.v1.MiscService",
					"Create",
				],
			},
			"expected": false,
		},
	]

	t := tests[_]
	actual := allow with input as t.input
	actual != t.expected
	print(sprintf("failed test '%s'. expected %v, but got %v", [t.title, t.expected, actual]))
}
