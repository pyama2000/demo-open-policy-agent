# Login as admin
POST http://127.0.0.1:{{proxy_port}}/auth/login
{ "role": "admin" }

HTTP 200
[Captures]
role_admin: body

GET http://127.0.0.1:{{proxy_port}}/list
Authorization: Basic {{role_admin}}

HTTP 200
