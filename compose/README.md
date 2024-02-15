# Compose files for IAM and OPA

This repo contains docker-compose files to run IAM and OPA.

## Run and play with OPA

Run the OPA service behind an NGINX reverse proxy with

```
$ docker-compose -f compose/docker-compose-opa.yml up -d
```

and wait for the trust anchor job to finish (cross-check that nginx is up and running afterwards).

To resolve the OPA hostname behind the docker network, add to your `/etc/hosts` file something like

```
# OPA
127.0.0.1    opa.test.example
```

Check that OPA is up and running with

```
$ curl https://opa.test.example/health -k
{}
$ echo $?
0
```

OPA reorders the content rego files, data and input within a `data` object.
Check its content with

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
$ curl https://opa.test.example -k -s -d@../assets/opa/input-example.json  | jq
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

For more OPA commands please check the [README](../README.md) and [OPA documentation](https://www.openpolicyagent.org/docs/latest/).

## Run IAM + OPA