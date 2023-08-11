package envoy.authz

test_authz {
	not _test_no_authz_path
	not _test_is_allowed_permission
}

_test_no_authz_path {
	tests := [
		{
			"title": "no authorization for health check",
			"input": {"methods": ["GET"], "path": "/healthz"},
			"expected": true,
		},
		{
			"title": "no authorization for login",
			"input": {"methods": ["POST"], "path": "/auth/login"},
			"expected": true,
		},
		{
			"title": "only GET method allowed for health check",
			"input": {"methods": ["POST", "PUT", "DELETE"], "path": "/healthz"},
			"expected": false,
		},
		{
			"title": "only POST method allowed for login",
			"input": {"methods": ["GET", "PUT", "DELETE"], "path": "/auth/login"},
			"expected": false,
		},
	]

	t := tests[_]
	m := t.input.methods[_]
	actual := allow with input as {"attributes": {"request": {"http": {"method": m, "path": t.input.path}}}}
	actual != t.expected
	print(sprintf("failed test '%s'. expected %v, but got %v", [t.title, t.expected, actual]))
}

_test_is_allowed_permission {
	admin_authorization := "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.RUEndDEYvTTkstJM_EA3sd9f_Eukdid6hi1HwxtFXKc"
	guest_authorization := "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiZ3Vlc3QifQ.VUtSU2es2oeHAtfjYgaOfXeDKOYTUZ-GtRDE3pa5Acc"
	tests := [
		{
			"title": "only admin can create",
			"input": {
				"method": "POST",
				"path": "/create",
				"authorization": admin_authorization,
			},
			"expected": true,
		},
		{
			"title": "only admin can list",
			"input": {
				"method": "GET",
				"path": "/list",
				"authorization": admin_authorization,
			},
			"expected": true,
		},
		{
			"title": "only admin can POST something",
			"input": {
				"method": "POST",
				"path": "/something",
				"authorization": admin_authorization,
			},
			"expected": true,
		},
		{
			"title": "only guest can GET something",
			"input": {
				"method": "GET",
				"path": "/something",
				"authorization": guest_authorization,
			},
			"expected": true,
		},
		{
			"title": "other than admin cannot create",
			"input": {
				"method": "POST",
				"path": "/create",
				"authorization": guest_authorization,
			},
			"expected": false,
		},
		{
			"title": "other than admin cannot list",
			"input": {
				"method": "GET",
				"path": "/list",
				"authorization": guest_authorization,
			},
			"expected": false,
		},
		{
			"title": "other than admin cannot POST something",
			"input": {
				"method": "POST",
				"path": "/something",
				"authorization": guest_authorization,
			},
			"expected": false,
		},
		{
			"title": "other than guest cannot GET something",
			"input": {
				"method": "GET",
				"path": "/something",
				"authorization": admin_authorization,
			},
			"expected": false,
		},
		{
			"title": "invalid token cannot create",
			"input": {
				"method": "POST",
				"path": "/create",
				"authorization": "",
			},
			"expected": false,
		},
		{
			"title": "invalid token cannot list",
			"input": {
				"method": "GET",
				"path": "/list",
				"authorization": "",
			},
			"expected": false,
		},
		{
			"title": "invalid token cannot POST something",
			"input": {
				"method": "POST",
				"path": "/something",
				"authorization": "",
			},
			"expected": false,
		},
		{
			"title": "invalid token cannot GET something",
			"input": {
				"method": "GET",
				"path": "/something",
				"authorization": "",
			},
			"expected": false,
		},
	]

	t := tests[_]
	actual := allow with input as {"attributes": {"request": {"http": {
		"method": t.input.method,
		"path": t.input.path,
		"headers": {"authorization": t.input.authorization},
	}}}}
	actual != t.expected
	print(sprintf("failed test '%s'. expected %v, but got %v", [t.title, t.expected, actual]))
}
