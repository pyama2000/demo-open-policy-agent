```sh
docker compose up --wait

export TOKEN=$(
  grpcurl -plaintext \
    -d '{ "role": "ROLE_ADMIN" }' \
    127.0.0.1:10000 auth.v1.AuthService.Signin \
    | jq -r '.token'
)
grpcurl -plaintext \
  -H "Authorization: Bearer ${TOKEN}" \
  127.0.0.1:10000 \
  misc.v1.MiscService/List
```
