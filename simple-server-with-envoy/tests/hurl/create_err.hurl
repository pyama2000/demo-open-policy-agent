# Login as admin
POST http://127.0.0.1:{{proxy_port}}/auth/login
{ "role": "admin" }

HTTP 200
[Captures]
role_admin: body

# Login as guest
POST http://127.0.0.1:{{proxy_port}}/auth/login
{ "role": "guest" }

HTTP 200
[Captures]
role_guest: body

# Invalid method
GET http://127.0.0.1:{{proxy_port}}/create
Authorization: Basic {{role_admin}}

HTTP 403

# invalid role
POST http://127.0.0.1:{{proxy_port}}/create
Authorization: Basic {{role_guest}}

HTTP 403
