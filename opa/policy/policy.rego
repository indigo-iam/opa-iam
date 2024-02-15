package scope_policies

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.matching_algorithm as policy_nb

scopes_eq(policy_nb) := {scope |
	data.policies[policy_nb].matchingPolicy == "EQ"
	some scope in input.scopes
	some scope_eq in data.policies[policy_nb].scopes
	scope == scope_eq
}

scopes_path(policy_nb) := {scope |
	data.policies[policy_nb].matchingPolicy == "PATH"
	some scope in input.scopes
	some scope_path in data.policies[policy_nb].scopes
	startswith(scope, scope_path)
}

scopes_regexp(policy_nb) := {scope |
	data.policies[policy_nb].matchingPolicy == "REGEXP"
	some scope in input.scopes
	some scope_regexp in data.policies[policy_nb].scopes
	startswith(scope_regexp, "wlcg.groups:")
	startswith(scope, scope_regexp)
}

permit_policy(policy_nb) if data.policies[policy_nb].rule == "PERMIT"

deny_policy(policy_nb) if data.policies[policy_nb].rule == "DENY"

denied_scopes contains scope if {
	some policy in policy_nb.matched_policy
	deny_policy(policy)
	some scope in input.scopes
	scope in scopes_eq(policy)
}

denied_scopes contains scope if {
	some policy in policy_nb.matched_policy
	deny_policy(policy)
	some scope in input.scopes
	scope in scopes_path(policy)
}

denied_scopes contains scope if {
	some policy in policy_nb.matched_policy
	deny_policy(policy)
	some scope in input.scopes
	scope in scopes_regexp(policy)
}

filtered_scopes contains scope if {
	some scope in input.scopes
	not scope in denied_scopes
}
