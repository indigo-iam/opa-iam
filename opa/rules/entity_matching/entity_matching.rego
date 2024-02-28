package rules.entity_matching

import rego.v1

# OPA policy matching based on user/client uuid
matched_policy contains nb if {
	some nb
	input.actor.subject == data.policies[nb].actor.id
	data.policies[nb].actor.type == "subject"
}

# OPA policy matching based on group uuid
matched_policy contains nb if {
	some nb
	input.actor.groups[_] == data.policies[nb].actor.id
	data.policies[nb].actor.type == "group"
}

# IAM policy matching based on user uuid
matched_policy contains nb if {
	some nb
	input.actor.subject == data.policies[nb].account.uuid
	data.policies[nb].group == null
}

# IAM policy matching based on group uuid
matched_policy contains nb if {
	some nb
	input.actor.groups[_] == data.policies[nb].group.uuid
	data.policies[nb].account == null
}

# IAM policy matching all
matched_policy contains nb if {
	some nb
	data.policies[nb].group == null
	data.policies[nb].account == null
}