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
POST http://127.0.0.1:{{proxy_port}}/list
Authorization: Basic {{role_admin}}

HTTP 403

# Invalid role
GET http://127.0.0.1:{{proxy_port}}/list
Authorization: Basic {{role_guest}}

HTTP 403
