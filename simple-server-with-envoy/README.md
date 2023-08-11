```sh
docker compose up --wait

export TOKEN=$(
  curl -s -X POST \
    -H 'Content-Type: application/json' \
    -d '{ "role": "admin" }' \
    "http://127.0.0.1:${PROXY_PORT}/auth/login"
)
curl -v -X POST \
  -H "authorization: Bearer ${TOKEN}" \
  "http://127.0.0.1:${PROXY_PORT}/create"
```
