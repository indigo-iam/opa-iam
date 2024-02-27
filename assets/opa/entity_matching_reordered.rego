package rules.entity_matching_reordered

import rego.v1

# OPA policy matching based on user uuid
matched_policy contains nb if {
	nb := reorder_policy_by_uuid[input.id]
    some i in nb
	input.user.id == data.policies[i].actor.id
	data.policies[nb].actor.type == "account"
}

# OPA policy matching based on group uuid
matched_policy contains nb if {
	nb := reorder_policy_by_uuid[input.id]
	some i in nb
	input.user.groups[_] == data.policies[i].actor.id
	data.policies[nb].actor.type == "group"
}

# OPA policy matching based on client uuid
matched_policy contains nb if {
	nb := reorder_policy_by_uuid[input.id]
	some i in nb
	input.client.id == data.policies[i].actor.id
	data.policies[nb].actor.type == "client"
}

# IAM policy matching based on user uuid
matched_policy contains nb if {
	nb := reorder_policy_by_uuid[input.id]
    some i in nb
	input.user.id == data.policies[i].account.uuid
	data.policies[i].group == null
}

# IAM policy matching based on group uuid
matched_policy contains nb if {
	nb := reorder_policy_by_uuid[input.id]
    some i in nb
	input.user.groups[_] == data.policies[i].group.uuid
	data.policies[i].account == null
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
