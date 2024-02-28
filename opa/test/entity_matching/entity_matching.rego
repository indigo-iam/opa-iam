package test.entity_matching

import rego.v1

import data.rules.entity_matching as em


test_opa_format_group_policy_matched if {

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "/indigoiam",
                "type": "group"
            }
        }]

    nb_matched_policies := em.matched_policy 
        with input as mock_input_group
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_missing_input_group_not_match_opa_policy_format if {

    mock_input_actor_subject := "1234"

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "/indigoiam",
                "type": "group"
            }
        }]

    nb_matched_policies := em.matched_policy 
        with input.actor.subject as mock_input_actor_subject
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_opa_format_subject_policy_matched if {

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "Test Account",
                "type": "subject"
            }
        }]

    nb_matched_policies := em.matched_policy 
        with input as mock_input_account
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_missing_input_actor_subject_not_match_opa_policy_format if {

    mock_input_actor_groups := ["1234"]

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "Test User",
                "type": "subject"
            }
        }]

    nb_matched_policies := em.matched_policy 
        with input.actor.groups as mock_input_actor_groups
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_missing_data_type_do_not_match_opa_policy_format if {

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "/indigoiam"}
        }]

    nb_matched_policies := em.matched_policy 
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

    nb_matched_policies := em.matched_policy 
        with input as mock_input_group
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_missing_input_group_do_not_match_iam_policy_format if {

    mock_input_user_id := "1234"

    mock_data := [{
            "account": null,
            "group": {
                "location": "https://iam.example/scim/Groups/1234",
                "name": "indigoiam",
                "uuid": "1234"
            }
        }]

    nb_matched_policies := em.matched_policy 
        with input.user.id as mock_input_user_id
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_missing_data_type_do_not_match_iam_group_policy_format if {

    mock_data := [{
            "account": null
        }]

    nb_matched_policies := em.matched_policy 
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

    nb_matched_policies := em.matched_policy 
        with input as mock_input_account
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_missing_input_user_id_do_not_match_iam_policy_format if {

    mock_input_actor_groups := ["1234"]

    mock_data := [{
            "account": {
                "location": "https://iam.example/scim/Users/1234",
                "name": "test",
                "uuid": "1234"
            },
            "group": null
        }]

    nb_matched_policies := em.matched_policy 
        with input.actor.groups as mock_input_actor_groups
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_missing_data_type_do_not_match_iam_account_policy_format if {

    mock_data := [{
            "group": null
        }]

    nb_matched_policies := em.matched_policy 
        with input as mock_input_account
        with data.policies as mock_data
    
    count(nb_matched_policies) == 0
}

test_iam_format_all_policy_matched if {

    mock_data := [{
            "account": null,
            "group": null
        }]

    nb_matched_policies := em.matched_policy 
        with input as mock_input_account
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_same_id_matches_only_account if {

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "Test User",
                "type": "subject"}
        }]

    nb_matched_policies := em.matched_policy 
        with input as mock_input_same_id
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_same_id_matches_only_group if {

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "/indigoiam",
                "type": "group"}
        }]

    nb_matched_policies := em.matched_policy 
        with input as mock_input_same_id
        with data.policies as mock_data
    
    count(nb_matched_policies) == 1
}

test_same_id_matches_all_policies if {

    mock_data := [
        {
            "actor": {
                "id": "1234",
                "name": "Test User",
                "type": "subject"}
        },
        {
            "actor": {
                "id": "1234",
                "name": "/indigoiam",
                "type": "group"}
        },
        {
            "actor": {
                "id": "1234",
                "name": "Test Client",
                "type": "subject"}
        }]

    nb_matched_policies := em.matched_policy 
        with input as mock_input_same_id
        with data.policies as mock_data
    
    count(nb_matched_policies) == 3
}

mock_input_group := {
        "actor": {
            "subject": "999",
            "groups": ["1234"]
        }
    }

mock_input_account := {
        "actor": {"subject": "1234"}
    }

mock_input_same_id := {
        "actor": {
            "subject": "1234",
            "groups": ["1234"]
        }
    }