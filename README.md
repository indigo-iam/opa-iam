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

### Run tests

This repo contains also tests to the OPA rules.

Run OPA tests with

```
$ docker-compose -f compose/docker-compose-opa.yml exec opa bash -c "opa test /etc/opa/policy -v"
/etc/opa/policy/matching_algorithm_test.rego:
data.scope_policies_test.test_opa_format_policy_matched: PASS (445.645µs)
data.scope_policies_test.test_missing_input_type_do_not_match_opa_policy_format: PASS (227.547µs)
...

```

## Testing IAM + OPA

