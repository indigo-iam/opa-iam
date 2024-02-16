# Compose files for IAM and OPA

This repo contains docker-compose files to run IAM and OPA.

## Run and play with OPA

Run the OPA service behind an NGINX reverse proxy with

```
$ docker-compose -f compose/docker-compose-opa.yml up -d
```

and wait for the trust anchor job to finish -- cross-check that nginx is up and running afterwards e.g. with `watch docker-compose ps`.

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

### Query OPA

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
  ]
}
```

### Update a document

OPA reorders the content of rego files, data and input within a `data` object.
Check its content with

```
$ curl https://opa.test.example/v1/data -k -s | jq .result
{
  "default_decision": "rules/scope_policies",
  "policies": [
    {
      "actor": {
        "id": "1234",
        "name": "/indigoiam",
        "type": "group"
      },
      "description": "Grant storage scopes to indigoiam group",
      "matchingPolicy": "EQ",
      "rule": "DENY",
  ...
}
```

OPA supports the JSON Patch operation to update a document, as for [RFC6902](https://datatracker.ietf.org/doc/html/rfc6902).
For instance, in order to upload a policy which denies access to IAM admin scopes to the client identified by `1234`, one should submit the following request:

```
$ curl https://opa.test.example/v1/data/policies -k -XPATCH -H "Content-Type: application/json-patch+json" -d '[{"op": "add", "path": "-", "value": {
    "actor": {
        "id": "1234",
        "name": "client-credentials",
        "type": "client"
    },
    "description": "Deny access to admin scopes to client 1234",
    "matchingPolicy": "EQ",
    "rule": "DENY",
    "scopes": [
        "iam:admin.read",
        "iam:admin.write"
    ]
  }
}]'
```

Now, the client-vetting policy is appended to the previous ones

```
$ curl https://opa.test.example/v1/data/policies | jq .result
[
  {
    "actor": {
      "id": "1234",
      "name": "/indigoiam",
      "type": "group"
    },
    "description": "Grant storage scopes to indigoiam group",
  ...
  {
    "actor": {
      "id": "1234",
      "name": "client-credentials",
      "type": "client"
    },
    "description": "Deny access to admin scopes to client 1234",
    "matchingPolicy": "EQ",
    "rule": "DENY",
    "scopes": [
      "iam:admin.read",
      "iam:admin.write"
    ]
  }
]
```

and will be evaluated together with the existing policies.

For more OPA commands please check the [README](../README.md) and [OPA documentation](https://www.openpolicyagent.org/docs/latest/).

## Run IAM + OPA