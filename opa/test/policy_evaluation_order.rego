package test

import rego.v1

import data.rules

test_subject_permit_policy_overrides_group if {

    mock_input := {
            "actor": {
                "subject": "1234",
                "groups": ["5678"]
            },
            "scopes": [
                "test1", "test2"
            ]
        }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "Test account",
                "type": "subject"
            },
            "matchingPolicy": "EQ",
            "rule": "PERMIT",
            "scopes": [
                "test1"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "Test Group",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1", "test2"
            ]
        }
    ]

    test1_permission := rules.scope_permission("test1")
        with input as mock_input
        with data.policies as mock_policies

    test1_permission == "PERMIT"

    test2_permission := rules.scope_permission("test2")
        with input as mock_input
        with data.policies as mock_policies

    test2_permission == "DENY"

}

test_subject_deny_policy_overrides_group if {

    mock_input := {
            "actor": {
                "subject": "1234",
                "groups": ["5678"]
            },
            "scopes": [
                "test1", "test2"
            ]
        }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "Test account",
                "type": "subject"
            },
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "Test Group",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "PERMIT",
            "scopes": [
                "test1", "test2"
            ]
        }
    ]

    test1_permission := rules.scope_permission("test1")
        with input as mock_input
        with data.policies as mock_policies

    test1_permission == "DENY"

    test2_permission := rules.scope_permission("test2")
        with input as mock_input
        with data.policies as mock_policies

    test2_permission == "PERMIT"

}

test_group_permit_policy_overrides_all if {

    mock_input := {
            "actor": {
                "subject": "1234",
                "groups": ["5678"]
            },
            "scopes": [
                "test1",
                "test2"
            ]
        }

    mock_policies := [
        {
            "actor": {
                "id": "5678",
                "name": "Test account",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "PERMIT",
            "scopes": [
                "test1"
            ]
        },
        {
            "account": null,
            "group": null,
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1", "test2"
            ]
        }
    ]

    test1_permission := rules.scope_permission("test1")
        with input as mock_input
        with data.policies as mock_policies

    test1_permission == "PERMIT"

    test2_permission := rules.scope_permission("test2")
        with input as mock_input
        with data.policies as mock_policies

    test2_permission == "DENY"

}

test_group_deny_policy_overrides_all if {

    mock_input := {
            "actor": {
                "subject": "1234",
                "groups": ["5678"]
            },
            "scopes": [
                "test1",
                "test2"
            ]
        }

    mock_policies := [
        {
            "actor": {
                "id": "5678",
                "name": "Test account",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1"
            ]
        },
        {
            "account": null,
            "group": null,
            "matchingPolicy": "EQ",
            "rule": "PERMIT",
            "scopes": [
                "test1", "test2"
            ]
        }
    ]

    test1_permission := rules.scope_permission("test1")
        with input as mock_input
        with data.policies as mock_policies

    test1_permission == "DENY"

    test2_permission := rules.scope_permission("test2")
        with input as mock_input
        with data.policies as mock_policies

    test2_permission == "PERMIT"

}

test_all_deny_policy_applies_last if {

    mock_input := {
            "actor": {
                "subject": "1234",
                "groups": ["5678"]
            },
            "scopes": [
                "test1", "test2", "test3"
            ]
        }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "Test account",
                "type": "subject"
            },
            "matchingPolicy": "EQ",
            "rule": "PERMIT",
            "scopes": [
                "test1"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "Test Group",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "PERMIT",
            "scopes": [
                "test1", "test2"
            ]
        },
        {
            "account": null,
            "group": null,
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1", "test2", "test3"
            ]
        }
    ]

    test1_permission := rules.scope_permission("test1")
        with input as mock_input
        with data.policies as mock_policies

    test1_permission == "PERMIT"

    test2_permission := rules.scope_permission("test2")
        with input as mock_input
        with data.policies as mock_policies

    test2_permission == "PERMIT"

    test3_permission := rules.scope_permission("test3")
        with input as mock_input
        with data.policies as mock_policies

    test3_permission == "DENY"

}

test_all_permit_policy_applies_last if {

    mock_input := {
            "actor": {
                "subject": "1234",
                "groups": ["5678"]
            },
            "scopes": [
                "test1", "test2", "test3"
            ]
        }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "Test account",
                "type": "subject"
            },
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "Test Group",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1", "test2"
            ]
        },
        {
            "account": null,
            "group": null,
            "matchingPolicy": "EQ",
            "rule": "PERMIT",
            "scopes": [
                "test1", "test2", "test3"
            ]
        }
    ]

    test1_permission := rules.scope_permission("test1")
        with input as mock_input
        with data.policies as mock_policies

    test1_permission == "DENY"

    test2_permission := rules.scope_permission("test2")
        with input as mock_input
        with data.policies as mock_policies

    test2_permission == "DENY"

    test3_permission := rules.scope_permission("test3")
        with input as mock_input
        with data.policies as mock_policies

    test3_permission == "PERMIT"

}

test_scope_not_in_policy_is_allowed if {

    mock_input := {
            "actor": {
                "subject": "1234",
                "groups": ["5678"]
            },
            "scopes": [
                "test1", "test2", "test3", "test4"
            ]
        }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "Test account",
                "type": "subject"
            },
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "Test Group",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test2"
            ]
        },
        {
            "account": null,
            "group": null,
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test3"
            ]
        }
    ]

    test4_permission := rules.scope_permission("test4")
        with input as mock_input
        with data.policies as mock_policies

    test4_permission == "PERMIT"

}

test_permit_rule_in_multiple_group_policies_wins if {

    mock_input := {
            "actor": {
                "subject": "1234",
                "groups": ["5678", "9101"]
            },
            "scopes": [
                "test1"
            ]
        }

    mock_policies := [
        {
            "actor": {
                "id": "5678",
                "name": "Test Group",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "test1"
            ]
        },
        {
            "actor": {
                "id": "9101",
                "name": "Test Group",
                "type": "group"
            },
            "matchingPolicy": "EQ",
            "rule": "PERMIT",
            "scopes": [
                "test1"
            ]
        }
    ]

    test1_permission := rules.scope_permission("test1")
        with input as mock_input
        with data.policies as mock_policies

    test1_permission == "PERMIT"

}