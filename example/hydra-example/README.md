# Baffao Example with Ory Hydra

This is an example of how to use [Ory Hydra](https://www.ory.sh/hydra/docs/) with Baffao.

## Client Creation

First of all, you need to create a client in Ory Hydra. You can do this by using the following command:

```bash
hydra create client \
    --endpoint http://localhost:4445 \
    --grant-type authorization_code,refresh_token \
    --response-type code,id_token \
    --scope openid,offline_access,profile,email \
    --token-endpoint-auth-method client_secret_post \
    --redirect-uri http://127.0.0.1:3000/oauth/callback
```

This will create a client with the following parameters:

- `grant_types`: `authorization_code,refresh_token`
- `response_types`: `code,id_token`
- `scope`: `openid,offline_access,profile,email`
- `token_endpoint_auth_method`: `client_secret_post`
- `redirect_uris`: `http://127.0.0.1:3000/oauth/callback`
