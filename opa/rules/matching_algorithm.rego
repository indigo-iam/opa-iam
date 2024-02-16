package rules.matching_algorithm

import rego.v1

# OPA policy matching based on user, group, or client uuid
matched_policy contains nb if {
	some nb
	input.id == data.policies[nb].actor.id
	input.type == data.policies[nb].actor.type
}

# IAM policy matching based on group uuid
matched_policy contains nb if {
	some nb
	input.id == data.policies[nb].group.uuid
    data.policies[nb].account == null
    input.type == "group"
}

# IAM policy matching based on user uuid
matched_policy contains nb if {
	some nb
	input.id == data.policies[nb].account.uuid
    data.policies[nb].group == null
    input.type == "account"
}

# IAM policy matching all
matched_policy contains nb if {
	some nb
    data.policies[nb].group == null
	data.policies[nb].account == null
}