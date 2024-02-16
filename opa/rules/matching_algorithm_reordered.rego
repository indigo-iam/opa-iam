package rules.matching_algorithm_reordered

import rego.v1

# OPA policy matching based on user, group, or client uuid
matched_policy contains nb if {
	nb := reorder_policy_by_uuid[input.id]
    some i in nb
	input.type == data.policies[i].actor.type
}

# IAM policy matching based on group uuid
matched_policy contains nb if {
	nb := reorder_policy_by_uuid[input.id]
    some i in nb
	data.policies[i].account == null
	input.type == "group"
}

# IAM policy matching based on user uuid
matched_policy contains nb if {
	nb := reorder_policy_by_uuid[input.id]
    some i in nb
	data.policies[i].group == null
	input.type == "account"
}

# IAM policy matching all
matched_policy contains nb if {
    some nb
    data.policies[nb].group == null
	data.policies[nb].account == null
}

reorder_policy_by_uuid[uuid] contains nb if {
	some nb
	uuid := data.policies[nb].account.uuid
}

reorder_policy_by_uuid[uuid] contains nb if {
	some nb
	uuid := data.policies[nb].group.uuid
}

reorder_policy_by_uuid[uuid] contains nb if {
	some nb
	uuid := data.policies[nb].actor.id
}
