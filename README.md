# IAM OPA integration

This repo contains a deployment of IAM where the Scope Policy API is replaced by the OPA engine.

## Testing OPA

Run the OPA service behind an NGINX reverse proxy with

```
$ docker-compose -f docker-compose-opa.yml up -d
```

Check that OPA is up and running with

```
$ curl https://opa.test.example/health -k
{}
$ echo $?
0
```

Check the OPA data content with

```
$ curl https://opa.test.example/v1/data -k -s | jq .result
{
  "actor": {
    "id": "1234",
    "name": "/indigoiam",
    "type": "group"
  },
  "description": "Grant storage scopes to indigoiam group",
  "matchingPolicy": "PATH",
  "rule": "PERMIT",
...
}
```

## Testing IAM + OPA

