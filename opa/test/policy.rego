package test

import rego.v1

import data.rules.entity_matching
import data.rules


test_no_policies_matched if {

    mock_scopes := ["openid", "profile"]

    nb_matched_policies := entity_matching.matched_policy 
        with input.scopes as mock_scopes 
        with data.policies as mock_policies
    
    count(nb_matched_policies) == 0
}

test_two_policies_matched if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234"]
        },
        "scopes": [
            "openid",
            "compute.read:/slash/pippo",
            "storage.read:/slash/pippo",
            "storage.read:/cms/pippo",
            "storage.modify:/slash/",
            "wlcg.groups:/pippo"
        ]
    }

    nb_matched_policies := entity_matching.matched_policy
        with input as mock_input 
        with data.policies as mock_policies

    count(nb_matched_policies) == 2

}

test_eq_filter if {

    mock_input := {
        "actor": {"subject": "5678"},
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

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"iam:admin.read", "iam:admin.write"}
}

test_path_filter if {

    mock_input := {
        "actor": {"subject": "9101"},
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

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"storage.read:/another-test-user",
            "storage.create:/another-test-user",
            "storage.modify:/another-test-user",
            "storage.stage:/another-test-user"}
}

test_eq_path_filter_with_different_scopes if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234"]
        },
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

    allowed_scopes == {"openid",
        "storage.read:/cms/pippo",
        "storage.read:/slash/pippo",
        "wlcg.groups:/pippo"}

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"compute.read:/slash/pippo", "storage.modify:/slash/"}
}

test_eq_path_filter_with_same_scopes if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234"]
        },
        "scopes": [
            "openid",
            "storage.read:/pippo",
            "storage.create:/pippo"
        ]
    }

    mock_policies := [{
            "actor": {
                "id": "999",
                "name": "indigoiam",
                "type": "subject"
            },
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "storage.read:/pippo",
                "storage.create:/pippo"
            ]
        },
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "DENY",
            "matchingPolicy": "PATH",
            "scopes": [
                "storage.read:/",
                "storage.create:/"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid"}

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"storage.read:/pippo", "storage.create:/pippo"}
}

test_permit_subject_policy_wins if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234","5678"]
        },
        "scopes": [
            "openid",
            "wlcg.groups:/pippo/pluto"
        ]
    }

    mock_policies := [{
            "actor": {
                "id": "999",
                "name": "indigoiam",
                "type": "subject"
            },
            "rule": "PERMIT",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto",
            ]
        },
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "DENY",
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        },
        {
            "account": null,
            "group": null,
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid", "wlcg.groups:/pippo/pluto"}

}

test_deny_subject_policy_wins if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234","5678"]
        },
        "scopes": [
            "openid",
            "wlcg.groups:/pippo/pluto"
        ]
    }

    mock_policies := [{
            "actor": {
                "id": "999",
                "name": "indigoiam",
                "type": "subject"
            },
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        },
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "PERMIT",
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "PERMIT",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        },
        {
            "account": null,
            "group": null,
            "rule": "PERMIT",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid"}

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"wlcg.groups:/pippo/pluto"}

}

test_permit_group_policy_wins_over_all if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234","5678"]
        },
        "scopes": [
            "openid",
            "wlcg.groups:/pippo/pluto"
        ]
    }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "PERMIT",
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        },
        {
            "account": null,
            "group": null,
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid", "wlcg.groups:/pippo/pluto"}

}

test_deny_group_policy_wins_over_all if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234","5678"]
        },
        "scopes": [
            "openid",
            "wlcg.groups:/pippo/pluto"
        ]
    }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "DENY",
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        },
        {
            "account": null,
            "group": null,
            "rule": "PERMIT",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid"}

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"wlcg.groups:/pippo/pluto"}

}

test_permit_rule_in_multiple_group_policy_wins_over_all if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234","5678"]
        },
        "scopes": [
            "openid",
            "wlcg.groups:/pippo/pluto"
        ]
    }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "PERMIT",
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        },
        {
            "account": null,
            "group": null,
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid", "wlcg.groups:/pippo/pluto"}

}

test_deny_rule_in_multiple_group_policy_wins_over_all if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234","5678"]
        },
        "scopes": [
            "openid",
            "wlcg.groups:/pippo/pluto"
        ]
    }

    mock_policies := [
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "DENY",
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo"
            ]
        },
        {
            "actor": {
                "id": "5678",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        },
        {
            "account": null,
            "group": null,
            "rule": "PERMIT",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid"}

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"wlcg.groups:/pippo/pluto"}

}

test_permit_all_policy_applies_last if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234","5678"]
        },
        "scopes": [
            "openid",
            "storage.read:/pippo",
            "wlcg.groups:/pippo",
            "wlcg.groups:/pippo/pluto",
            "wlcg.groups:/pippo/pluto/paperino"
        ]
    }

    mock_policies := [{
            "actor": {
                "id": "999",
                "name": "indigoiam",
                "type": "subject"
            },
            "rule": "DENY",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo",
            ]
        },
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "DENY",
            "matchingPolicy": "PATH",
            "scopes": [
                "storage.read:/"
            ]
        },
        {
            "account": null,
            "group": null,
            "rule": "PERMIT",
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid", "wlcg.groups:/pippo/pluto", "wlcg.groups:/pippo/pluto/paperino"}

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"storage.read:/pippo", "wlcg.groups:/pippo"}

}

test_deny_all_policy_applies_last if {

    mock_input := {
        "actor": {
            "subject": "999",
            "groups": ["1234","5678"]
        },
        "scopes": [
            "openid",
            "storage.read:/pippo",
            "wlcg.groups:/pippo",
            "wlcg.groups:/pippo/pluto",
            "wlcg.groups:/pippo/pluto/paperino"
        ]
    }

    mock_policies := [{
            "actor": {
                "id": "999",
                "name": "indigoiam",
                "type": "subject"
            },
            "rule": "PERMIT",
            "matchingPolicy": "EQ",
            "scopes": [
                "wlcg.groups:/pippo",
            ]
        },
        {
            "actor": {
                "id": "1234",
                "name": "indigoiam",
                "type": "group"
            },
            "rule": "PERMIT",
            "matchingPolicy": "PATH",
            "scopes": [
                "storage.read:/"
            ]
        },
        {
            "account": null,
            "group": null,
            "rule": "DENY",
            "matchingPolicy": "PATH",
            "scopes": [
                "wlcg.groups:/pippo/pluto"
            ]
        }]

    allowed_scopes := rules.filtered_scopes
        with input as mock_input
        with data.policies as mock_policies

    allowed_scopes == {"openid", "storage.read:/pippo", "wlcg.groups:/pippo"}

    denied_scopes := rules.denied_scopes
        with input as mock_input
        with data.policies as mock_policies

    denied_scopes == {"wlcg.groups:/pippo/pluto", "wlcg.groups:/pippo/pluto/paperino"}

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
                "type": "subject"
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
                "type": "subject"
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
        }
    ]
