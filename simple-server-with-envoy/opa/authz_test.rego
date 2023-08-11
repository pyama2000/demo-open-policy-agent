package envoy.authz

test_authz {
	not _test_no_authz_path
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
