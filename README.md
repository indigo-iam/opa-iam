# IAM OPA integration

This repo contains a deployment of IAM where the Scope Policy API is replaced by the OPA engine.

## Testing OPA

Run the OPA service behind an NGINX reverse proxy with

```
$ docker-compose -f compose/docker-compose-opa.yml up -d
```

and wait for the trust anchor job to finish (cross-check that nginx is up and running afterwards).

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

Query the OPA engine with an input file as example

```
$ curl https://opa.test.example -k -s -d@assets/opa/input-example.json  | jq
{
  "denied_scopes": [
    "compute.read:/slash/pippo",
    "storage.modify:/slash/"
  ],
  "filtered_scopes": [
    "openid",
    "storage.read:/cms/pippo",
    "storage.read:/slash/pippo",
    "wlcg.groups:/pippo"
  ],
  "matched_policy": [
    0,
    1
  ]
}
```

## Testing IAM + OPA

