package test

import rego.v1

import data.rules

test_eq_matching if {

    mock_input := [
            "openid",
            "iam:admin.read",
            "iam:admin.write"
        ]

    mock_policies := [{
            "matchingPolicy": "EQ",
            "scopes": [
                "iam:admin.read",
                "iam:admin.write"
            ]
        }]

    matched_scopes := rules.scopes_eq(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes == {"iam:admin.read", "iam:admin.write"}
}

test_eq_not_matched if {

    mock_input := [
            "openid",
            "iam:admin",
            "iam:admin"
        ]

    mock_policies := [{
            "matchingPolicy": "EQ",
            "scopes": [
                "iam:admin.read",
                "iam:admin.write"
            ]
        }]

    matched_scopes := rules.scopes_eq(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    count(matched_scopes) == 0
}

test_path_matching if {

    mock_input := [
            "openid",
            "storage.read:/another-test-user",
            "storage.create:/another-test-user",
            "storage.modify:/another-test-user",
            "storage.stage:/another-test-user"
        ]

    mock_policies := [{
            "matchingPolicy": "PATH",
            "scopes": [
                "storage.read:/",
                "storage.create:/",
                "storage.modify:/",
                "storage.stage:/"
            ]
        }]

    matched_scopes := rules.scopes_path(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes == {"storage.read:/another-test-user", "storage.create:/another-test-user", "storage.modify:/another-test-user", "storage.stage:/another-test-user"}
}

test_path_not_matched if {

    mock_input := [
            "openid",
            "storage.read:/",
            "storage.create:/",
            "storage.modify:/",
            "storage.stage:/"
        ]

    mock_policies := [{
            "matchingPolicy": "PATH",
            "scopes": [
                "storage.read:/another-test-user",
                "storage.create:/another-test-user",
                "storage.modify:/another-test-user",
                "storage.stage:/another-test-user"
            ]
        }]

    matched_scopes := rules.scopes_path(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    count(matched_scopes) == 0
}

test_regexp_matching if {

    mock_input := [
            "openid",
            "wlcg.groups:/pippo/pluto"
        ]

    mock_policies := [{
            "matchingPolicy": "REGEXP",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        }]

    matched_scopes := rules.scopes_regexp(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes == {"wlcg.groups:/pippo/pluto"}
}

test_regexp_not_matched if {

    mock_input := [
            "openid",
            "wlcg.groups:/pluto"
        ]

    mock_policies := [{
            "matchingPolicy": "REGEXP",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        }]

    matched_scopes := rules.scopes_regexp(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    count(matched_scopes) == 0
}

test_eq_path_matching_with_different_scopes if {

    mock_input := [
            "openid",
            "iam:admin.read",
            "iam:admin.write",
            "storage.read:/pippo",
            "storage.create:/pippo"
        ]

    mock_policies := [{
            "matchingPolicy": "EQ",
            "scopes": [
                "iam:admin.read",
                "iam:admin.write"
            ]
        },
        {
            "matchingPolicy": "PATH",
            "scopes": [
                "storage.read:/",
                "storage.create:/"
            ]
        }]

    matched_scopes_eq := rules.scopes_eq(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_eq == {"iam:admin.read", "iam:admin.write"}

    matched_scopes_path := rules.scopes_path(1)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_path == {"storage.read:/pippo", "storage.create:/pippo"}
}

test_eq_path_matching_with_same_scopes if {

    mock_input := [
            "openid",
            "storage.read:/pippo",
            "storage.create:/pippo"
        ]

    mock_policies := [{
            "matchingPolicy": "EQ",
            "scopes": [
                "storage.read:/pippo",
                "storage.create:/pippo"
            ]
        },
        {
            "matchingPolicy": "PATH",
            "scopes": [
                "storage.read:/",
                "storage.create:/"
            ]
        }]

    matched_scopes_eq := rules.scopes_eq(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_eq == {"storage.read:/pippo", "storage.create:/pippo"}

    matched_scopes_path := rules.scopes_path(1)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_path == {"storage.read:/pippo", "storage.create:/pippo"}
}

test_eq_path_regexp_matching_with_different_scopes if {

    mock_input := [
            "openid",
            "iam:admin.read",
            "iam:admin.write",
            "storage.read:/pippo",
            "storage.create:/pippo",
            "wlcg.groups:/pippo/pluto"
        ]

    mock_policies := [{
            "matchingPolicy": "EQ",
            "scopes": [
                "iam:admin.read",
                "iam:admin.write"
            ]
        },
        {
            "matchingPolicy": "PATH",
            "scopes": [
                "storage.read:/",
                "storage.create:/"
            ]
        },
        {
            "matchingPolicy": "REGEXP",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        }]

    matched_scopes_eq := rules.scopes_eq(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_eq == {"iam:admin.read", "iam:admin.write"}

    matched_scopes_path := rules.scopes_path(1)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_path == {"storage.read:/pippo", "storage.create:/pippo"}

    matched_scopes_regexp := rules.scopes_regexp(2)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_regexp == {"wlcg.groups:/pippo/pluto"}
}

test_eq_path_regexp_matching_with_same_scope if {

    mock_input := [
            "openid",
            "wlcg.groups:/pippo/pluto"
        ]

    mock_policies := [{
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        },
        {
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        },
        {
            "matchingPolicy": "REGEXP",
            "scopes": [
                "wlcg.groups:/"
            ]
        }]

    matched_scopes_eq := rules.scopes_eq(0)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_eq == {"wlcg.groups:/pippo/pluto"}

    matched_scopes_path := rules.scopes_path(1)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_path == {"wlcg.groups:/pippo/pluto"}

    matched_scopes_regexp := rules.scopes_regexp(2)
        with input.scopes as mock_input
        with data.policies as mock_policies

    matched_scopes_regexp == {"wlcg.groups:/pippo/pluto"}
}