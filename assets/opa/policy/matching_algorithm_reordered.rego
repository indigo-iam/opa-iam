package matching_algorithm_reordered

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# OPA policy matching based on user, group, or client uuid
matched_policy contains nb if {
	some nb
    nb in reorder_policy_by_uuid[input.id]
	input.type == data.policies[nb].actor.type
}

# IAM policy matching based on group uuid
matched_policy contains nb if {
	some nb
    nb in reorder_policy_by_uuid[input.id]
	data.policies[nb].account == null
	input.type == "group"
}

# IAM policy matching based on user uuid
matched_policy contains nb if {
	some nb
    nb in reorder_policy_by_uuid[input.id]
	data.policies[nb].group == null
	input.type == "account"
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
