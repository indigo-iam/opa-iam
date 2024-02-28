package test

import rego.v1

import data.rules


test_opa_format_group_entity_matched if {

    mock_data := [{
            "actor": {
                "type": "group"
            }
        }]

    policy_is_group := rules.group_policy(0)
        with data.policies as mock_data
    
    policy_is_group
}

test_missing_group_type_not_match_opa_entity_format if {

    mock_data := [{
            "actor": {
                "id": "1234",
                "name": "/indigoiam"
            }
        }]

    policy_is_group := rules.group_policy(0)
        with data.policies as mock_data
    
    not policy_is_group
}

test_opa_format_subject_entity_matched if {

    mock_data := [{
            "actor": {
                "type": "subject"
            }
        }]

    policy_is_subject := rules.subject_policy(0) 
        with data.policies as mock_data
    
    policy_is_subject
}

test_missing_subject_type_not_match_opa_entity_format if {

    mock_data := [{
                "actor": {
                    "id": "1234",
                    "name": "Test Account"
                }
        }]

    policy_is_subject := rules.subject_policy(0) 
        with data.policies as mock_data
    
    not policy_is_subject
}

test_iam_format_group_entity_matched if {

    mock_data := [{
            "account": null,
            "group": {
                "uuid": "1234"
            }
        }]

    policy_is_group := rules.group_policy(0) 
        with data.policies as mock_data
    
    policy_is_group
}

test_missing_group_uuid_not_match_iam_entity_format if {

    mock_data := [{
            "account": null,
            "group": {
                "location": "https://iam.example/scim/Groups/1234",
                "name": "indigoiam"
            }
        }]

    policy_is_group := rules.group_policy(0) 
        with data.policies as mock_data
    
    not policy_is_group
}

test_missing_account_key_not_match_iam_group_format if {

    mock_data := [{
            "group": {
                "location": "https://iam.example/scim/Groups/1234",
                "name": "indigoiam",
                "uuid": "1234"
            }
        }]

    policy_is_group := rules.group_policy(0) 
        with data.policies as mock_data
    
    not policy_is_group
}

test_iam_format_account_entity_matched if {

    mock_data := [{
            "account": {
                "location": "https://iam.example/scim/Users/1234",
                "name": "test",
                "uuid": "1234"
            },
            "group": null
        }]

    policy_is_subject := rules.subject_policy(0) 
        with data.policies as mock_data
    
    policy_is_subject
}

test_missing_account_uuid_not_match_iam_entity_format if {

    mock_data := [{
            "account": {
                "location": "https://iam.example/scim/Users/1234",
                "name": "test"
            },
            "group": null
        }]

    policy_is_subject := rules.subject_policy(0) 
        with data.policies as mock_data
    
    not policy_is_subject
}

test_missing_group_key_not_match_iam_account_format if {

    mock_data := [{
            "account": {
                "location": "https://iam.example/scim/Users/1234",
                "name": "test",
                "uuid": "1234"
            }
        }]

    policy_is_subject := rules.subject_policy(0) 
        with data.policies as mock_data
    
    not policy_is_subject
}

test_iam_format_all_entity_matched if {

    mock_data := [{
            "account": null,
            "group": null
        }]

    policy_is_all := rules.all_policy(0) 
        with data.policies as mock_data
    
    policy_is_all
}

test_opa_format_all_entity_matched if {

    mock_data := [{
            "account": null,
            "group": null
        }]

    policy_is_all := rules.all_policy(1) 
        with data.policies as mock_data
    
    policy_is_all
}