# IAM OPA integration

This repo contains a deployment of IAM where the Scope Policy API is replaced by the OPA engine.

## Run and play with OPA

You can use the docker-compose [file](docker-compose.yml) to run the OPA service:

```
$ docker-compose up -d
```

Query the OPA engine with an input file as example

```
$ curl http://localhost:8181 -s -d@assets/opa/input-example.json  | jq
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

### Profiling

The OPA command line offers a simple tool to profile the policy evaluation trough the `opa eval` command.

For instance, evaluate the output of the `denied_scopes` variable and enable the profiler with

```
$ docker-compose exec opa bash
$ opa eval -i /opa-examples/input-example.json -d /etc/opa/rules -d /opa-examples/data-10k.json  "data.rules.scope_policies.denied_scopes" --profile-sort total_time_ns --format=pretty --count=10
[
  "compute.read:/slash/pippo",
  "storage.modify:/slash/"
]
+--------------------------------+---------+---------+---------------+------------------------+--------------+
|             METRIC             |   MIN   |   MAX   |     MEAN      |          90%           |     99%      |
+--------------------------------+---------+---------+---------------+------------------------+--------------+
| timer_rego_data_parse_ns       | 33450   | 50068   | 37877.6       | 49711.6                | 50068        |
| timer_rego_external_resolve_ns | 732     | 1920    | 974.3         | 1834.0000000000005     | 1920         |
| timer_rego_load_files_ns       | 617935  | 1154446 | 845814        | 1.1407993e+06          | 1.154446e+06 |
| timer_rego_module_compile_ns   | 1997613 | 3779267 | 2.4696142e+06 | 3.6853316000000006e+06 | 3.779267e+06 |
| timer_rego_module_parse_ns     | 470806  | 903877  | 666106.3      | 900125.6               | 903877       |
| timer_rego_query_compile_ns    | 34278   | 186998  | 59109.5       | 175375.60000000003     | 186998       |
| timer_rego_query_eval_ns       | 597357  | 1397853 | 788956.3      | 1.3434870000000002e+06 | 1.397853e+06 |
| timer_rego_query_parse_ns      | 36340   | 109625  | 50308.4       | 104012.20000000001     | 109625       |
+--------------------------------+---------+---------+---------------+------------------------+--------------+
+----------+-----------+-----------+-----------+-----------+----------+----------+--------------+--------------------------------------------+
|   MIN    |    MAX    |   MEAN    |    90%    |    99%    | NUM EVAL | NUM REDO | NUM GEN EXPR |                  LOCATION                  |
+----------+-----------+-----------+-----------+-----------+----------+----------+--------------+--------------------------------------------+
| 63.377µs | 385.407µs | 119.999µs | 363.09µs  | 385.407µs | 24       | 13       | 2            | /etc/opa/policy/policy.rego:39             |
| 59.457µs | 125.181µs | 78.179µs  | 123.796µs | 125.181µs | 24       | 13       | 2            | /etc/opa/policy/policy.rego:46             |
| 54.621µs | 97.817µs  | 66.485µs  | 95.337µs  | 97.817µs  | 1        | 2        | 1            | /etc/opa/rules/entity_matching/entity_matching.rego:12 |
| 44.85µs  | 93.39µs   | 57.815µs  | 90.187µs  | 93.39µs   | 24       | 12       | 2            | /etc/opa/policy/policy.rego:53             |
| 37.416µs | 80.412µs  | 49.533µs  | 77.877µs  | 80.412µs  | 1        | 1        | 1            | data.scope_policies.denied_scopes          |
| 31.168µs | 68.767µs  | 43.402µs  | 66.896µs  | 68.767µs  | 6        | 18       | 1            | /etc/opa/policy/policy.rego:12             |
| 22.924µs | 62.574µs  | 36.244µs  | 60.584µs  | 62.574µs  | 6        | 12       | 1            | /etc/opa/policy/policy.rego:19             |
| 21.622µs | 50.835µs  | 29.548µs  | 49.712µs  | 50.835µs  | 2        | 12       | 1            | /etc/opa/policy/policy.rego:45             |
| 21.204µs | 38.971µs  | 25.441µs  | 37.708µs  | 38.971µs  | 2        | 12       | 1            | /etc/opa/policy/policy.rego:38             |
| 17.89µs  | 38.186µs  | 23.784µs  | 36.896µs  | 38.186µs  | 2        | 12       | 1            | /etc/opa/policy/policy.rego:52             |
+----------+-----------+-----------+-----------+-----------+----------+----------+--------------+--------------------------------------------+
```

where
* `--profile-sort` option sorts the output by the total time the query has been computed, in nanoseconds (this option includes `--profile`)
* `--format=pretty` enables the output as table format (default is JSON)
* `--count=10` repeats the policy evaluation 10 time and enables statistics results.

For more options and documentation to the OPA profiling click [here](https://www.openpolicyagent.org/docs/latest/policy-performance/#profiling).

### Run tests

This repo contains also tests to the OPA rules.

Run OPA tests with

```
$ docker-compose exec opa bash -c "opa test /etc/opa -v"
/etc/opa/test/entity_matching/entity_matching.rego:
data.test.entity_matching.test_opa_format_policy_matched: PASS (445.645µs)
data.test.entity_matching.test_missing_input_type_do_not_match_opa_policy_format: PASS (227.547µs)
...

```

### Install OPA locally

Download the latest OPA version to date for Linux (see [here](https://www.openpolicyagent.org/docs/latest/#1-download-opa) for other distributions) with

```
$ curl -L -o opa-cli https://github.com/open-policy-agent/opa/releases/download/v0.61.0/opa_linux_amd64
$ chmod 755 opa-cli
```

All the above `opa` commands will run in the same way as with docker-compose, using `opa-cli`.

Build the OPA rego files (together with data) and create the bundle with

```
$ ./opa-cli build -b opa/ -o opa-bundle.tar.gz
```

Start the server with

```
$ ./opa-cli run --server -b opa-bundle.tar.gz -c opa/config.yaml --log-level debug
```

## Testing IAM + OPA

## Open issues

* Decide which policy takes the precedence, based on "actor" type (account, group or client)
  * [issue 2](https://baltig.infn.it/fagostin/iam-opa-integration/-/issues/2)
* Need to implement a real PATH algorithm to match scopes -- right now is just a prefix match
  * [issue 3](https://baltig.infn.it/fagostin/iam-opa-integration/-/issues/3)
* Do we want to add and evaluate also audience with OPA? How?
  * [issue 1](https://baltig.infn.it/fagostin/iam-opa-integration/-/issues/1)
* Not sure if there is a more friendly way to upload policies than JSON Patch (documented in [OPA](https://www.openpolicyagent.org/docs/latest/rest-api/#patch-a-document) and [here](compose/README.md#update-a-document))
* Do we want to keep this repo or migrate it to indigo-iam?
* Find a way to source from a file when testing
* If someone has in mind some test cases to add is very welcome!