package test.scope_policies

import rego.v1

import data.rules.matching_algorithm_reordered as ma
import data.rules.scope_policies as rules


test_opa_format_policy_matched if {

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "/indigoiam",
                "type": "group"
            }
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input_group
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_opa_format_client_policy_matched if {
    mock_input_group := {
        "id": "1234",
        "type": "client"
    }

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "client-credentials",
                "type": "client"
            }
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input_group
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_missing_input_type_do_not_match_opa_policy_format if {

    mock_input := {"id": "1234"}

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "/indigoiam",
                "type": "group"
            }
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_missing_data_type_do_not_match_opa_policy_format if {

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "/indigoiam"}
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input_group
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_iam_format_group_policy_matched if {

    mock_data := [{
            "account": null,
            "group": {
                "location": "https://iam.example/scim/Groups/1234",
                "name": "indigoiam",
                "uuid": "1234"
            }
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input_group
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_missing_input_type_do_not_match_iam_group_policy_format if {

    mock_input := {"id": "1234"}

    mock_data := [{
            "account": null,
            "group": {
                "location": "https://iam.example/scim/Groups/1234",
                "name": "indigoiam",
                "uuid": "1234"
            }
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_missing_data_type_do_not_match_iam_group_policy_format if {

    mock_data := [{
            "account": null
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input_group
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_iam_format_account_policy_matched if {

    mock_data := [{
            "account": {
                "location": "https://iam.example/scim/Users/1234",
                "name": "test",
                "uuid": "1234"
            },
            "group": null
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input_account
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_missing_input_type_do_not_match_iam_account_policy_format if {

    mock_input := {"id": "1234"}

    mock_data := [{
            "account": {
                "location": "https://iam.example/scim/Users/1234",
                "name": "test",
                "uuid": "1234"
            },
            "group": null
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_missing_data_type_do_not_match_iam_account_policy_format if {

    mock_data := [{
            "group": null
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input_account
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_iam_format_all_policy_matched if {

    mock_data := [{
            "account": null,
            "group": null
        }]

    nb_matched_policies := ma.matched_policy 
        with input as mock_input_account
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

mock_input_group := {
        "id": "1234",
        "type": "group"
    }

mock_input_account := {
        "id": "1234",
        "type": "account"
    }