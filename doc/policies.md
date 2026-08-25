# OPA policies

The scope policies are a list of policies which define if an account, a client, a group or everybody can obtain or not a list of defined scopes.

As for the INDIGO IAM scope policies, a policy applied to an account overrides a policy applied to a group, which overrides a policy applied to everybody. Moreover, in OPA we allow to add policies for clients, which are considered in the same way as an account.

The policy schema supported by OPA is explained below. Anyway, for backward compatibility also the INDIGO IAM policy schema is supported, meaning that you can simply download the scope policies form IAM and the OPA policy engine will work in the same way as Java engine.

## Data schema

In OPA, the policies should be written in a _data.json_ file with the following schema (see [data.json](../opa/policies/data.json) for example)

```json
{   "policies":
    [
        {
            policyObject1
        },
        {
            policyObject2
        },
        ...
    ]
}
```

## Policy schema

A typical policy schema is the following

```json
{
    "actor": {
        "id": <uuid>,
        "type": account|client|group
    },
    "matchingPolicy": EQ|PATH,
    "rule": PERMIT|DENY,
    "scopes": [
        <list-of-scopes>
    ]
}
```

Differently from INDIGO IAM, here we decide to not support the `REGEXP` _matchingPolicy_ algorithm.

### Actor

A scope policy may be applied to an account, a client, a group or all.

An example of account policy is the following

```json
{
    "actor": {
        "id": "73f16d93-2441-4a50-88ff-85360d78c6b5",
        "name": "Admin User", # Not mandatory
        "type": "account"
    },
    "description": "Deny offline_access scope to Admin User", # Not mandatory
    "matchingPolicy": "EQ",
    "rule": "DENY",
    "scopes": [
         "offline_access"
    ]
}
```

An example of client policy is

```json
{
    "actor": {
        "id": "71e2fe91-1f85-4333-9098-406a1a36292a",
        "name": "Test Client", # Not mandatory
        "type": "client"
    },
    "description": "Deny phone scope to Test Client", # Not mandatory
    "matchingPolicy": "EQ",
    "rule": "DENY",
    "scopes": [
         "phone"
    ]
}
```

An example of group policy can be

```json
{
    "actor": {
        "id": "31d9230c-90ae-4457-a990-0c443ab4aacc",
        "name": "xfer", # Not mandatory
        "type": "group"
    },
    "description": "Allow storage.stage:/ scope to members of xfer group", # Not mandatory
    "matchingPolicy": "PATH",
    "rule": "PERMIT",
    "scopes": [
         "storage.stage:/"
    ]
}
```

A policy which can be applied to everybody is

```json
{
    "actor": {
        "name": "all" # Not mandatory
    },
    "description": "Allow openid scope to everybody", # Not mandatory
    "matchingPolicy": "PATH",
    "rule": "PERMIT",
    "scopes": [
         "openid"
    ]
}
```

## Build policy bundle

In order for OPA to read the above policies, you need to build the policy bundle as explained [here](./testing.md#build-bundle). Then, add a proper OPA configuration to source from this bundle, as reported in this [documentation](./configuration.md#yaml-file).