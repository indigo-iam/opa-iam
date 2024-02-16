package test.scope_policies

import rego.v1

import data.rules.matching_algorithm
import data.rules.scope_policies as rules


test_no_policies_matched if {

    mock_scopes := ["openid", "profile"] 

    nb_matched_policies := matching_algorithm.matched_policy 
        with input.scopes as mock_scopes 
        with data.policies as mock_policies
    
    count(nb_matched_policies) == 0
}

test_two_policies_matched if {

    mock_input := {
        "id": "1234",
        "type": "group",
        "scopes": [
            "openid",
            "compute.read:/slash/pippo",
            "storage.read:/slash/pippo",
            "storage.read:/cms/pippo",
            "storage.modify:/slash/",
            "wlcg.groups:/pippo"
        ]
    }

    nb_matched_policies := matching_algorithm.matched_policy
        with input as mock_input 
        with data.policies as mock_policies

    count(nb_matched_policies) == 2

}

test_eq_filter if {

    mock_input := {
        "id": "5678",
        "type": "account",
        "scopes": [
            "openid",
            "iam:admin.read",
            "iam:admin.write"
        ]
    }

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid"}
}

test_path_filter if {

    mock_input := {
        "id": "9101",
        "type": "account",
        "scopes": [
            "openid",
            "storage.read:/another-test-user",
            "storage.create:/another-test-user",
            "storage.modify:/another-test-user",
            "storage.stage:/another-test-user"
        ]
    }

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid"}
}

test_eq_path_filter if {

    mock_input := {
        "id": "1234",
        "type": "group",
        "scopes": [
            "openid",
            "compute.read:/slash/pippo",
            "storage.read:/slash/pippo",
            "storage.read:/cms/pippo",
            "storage.modify:/slash/",
            "wlcg.groups:/pippo"
        ]
    }

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid", "storage.read:/cms/pippo", "storage.read:/slash/pippo", "wlcg.groups:/pippo"}
}

test_regexp_filter if {

    mock_input := {
        "id": "999",
        "type": "group",
        "scopes": [
            "openid",
            "wlcg.groups:/pippo"
        ]
    }

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid"}
}

mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "description": "Deny storage scopes to indigoiam group",
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "storage.read:/slash/",
                "storage.create:/slash/",
                "storage.modify:/slash/"
            ]
        },
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "description": "Deny storage/compute scopes to indigoiam group",
            "matchingPolicy": "PATH",
            "rule": "DENY",
            "scopes": [
                "storage.modify:/test",
                "compute.read:/slash/"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "test-user",
                "type": "account"
            },
            "description": "Deny admin scopes to test-user",
            "matchingPolicy": "EQ",
            "rule": "DENY",
            "scopes": [
                "iam:admin.read",
                "iam:admin.write"
            ]
        },
        {
            "actor": {
                "id": "9101",
                "name": "another-test-user",
                "type": "account"
            },
            "description": "Deny storage scopes to another-test-user",
            "matchingPolicy": "PATH",
            "rule": "DENY",
            "scopes": [
                "storage.read:/",
                "storage.create:/",
                "storage.modify:/",
                "storage.stage"
            ]
        },
        {
            "actor": {
                "id": "999",
                "name": "/indigoiam",
                "type": "group"
            },
            "description": "Deny wlcg.group scope to indigoiam group",
            "matchingPolicy": "REGEXP",
            "rule": "DENY",
            "scopes": [
                "wlcg.groups:/pipp"
            ]
        }
    ]
