POST http://127.0.0.1:{{proxy_port}}/auth/login
{ "role": "admin" }

HTTP 200
[Captures]
role_admin: body

POST http://127.0.0.1:{{proxy_port}}/create
Authorization: Basic {{role_admin}}

HTTP 201
