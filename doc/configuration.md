# OPA configuration

## Bundle

The following configuration allows to run OPA polling from bundles. If you want to investigate more about OPA bundles, please check the [documentation](https://www.openpolicyagent.org/docs/management-bundles).

Here we use two different bundles for OPA:
- a general bundle published on the [GitHub registry](https://github.com/indigo-iam/opa-iam/pkgs/container/opa-iam) containing the scope policy logic (i.e. _rego_ files)
- a bundle which defines the policies to be applied, in a JSON format. An example is shown in the [data.json](../opa/policies/data.json) file. This bundle is specific per VO (i.e. INDIGO IAM instance), so it must be defined and built before to start OPA. To know how to build this bundle, please check the [documentation](./testing.md#build-bundle).

## YAML file

A minimal configuration YAML file for OPA can be found in the [conf](../conf/config-pull.yaml) folder,
and basically it is

```yaml
services:
  gh:
    url: https://ghcr.io
    type: oci
  local:
    url: file:///</full/path/to/your/policy-bundle.tar.gz>

bundles:
  scope-policy-engine:
    service: gh
    resource: ghcr.io/indigo-iam/opa-iam:multi-bundle
  policies:
    service: local
    resource: file:///<full/path/to/your/policy-bundle.tar.gz>

default_decision: rules
```

If you want to persist the bundle, add

```yaml
bundles:
  <scope-policy-engine|policies>:
    persist: true

persistence_directory: </directory/for/persistence>
```

in case you want to customize the polling period, add

```yaml
bundles:
  <scope-policy-engine|policies>:
    polling:
      min_delay_seconds: 10 # default to 300
      max_delay_seconds: 20 # default to 600
```

If you want to log decision information, including request body, response body (that are also shown with the logging level set to DEBUG) and methrics add

```yaml
decision_logs:
  console: true
```

For other configuration parameters see the OPA [documentation](https://www.openpolicyagent.org/docs/configuration).