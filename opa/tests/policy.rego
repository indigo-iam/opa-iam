package test.scope_policies

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.policy.matching_algorithm
import data.policy.scope_policies as rules


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
                "name": "/indigoiam",
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
                "name": "Test Client",
                "type": "group"
            },
            "description": "Deny storage/compute scopes to Test Client",
            "matchingPolicy": "PATH",
            "rule": "DENY",
            "scopes": [
                "storage.modify:/test",
                "compute.read:/slash/"
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
        },
        {
            "account": null,
            "creationTime": "2020-03-05T14:27:56.000+01:00",
            "description": "Deny access to storage scopes for cms to escape/cms users",
            "group": {
                "location": "https://iam-escape.cloud.cnaf.infn.it/scim/Groups/97373f9d-3ba3-4006-b849-dbb6cca517d1",
                "name": "escape/cms",
                "uuid": "97373f9d-3ba3-4006-b849-dbb6cca517d1"
            },
            "id": 14,
            "lastUpdateTime": "2020-03-05T14:27:56.000+01:00",
            "matchingPolicy": "PATH",
            "rule": "DENY",
            "scopes": [
                "storage.read:/cms",
                "storage.create:/cms",
                "storage.modify:/cms"
            ]
        }
    ]
