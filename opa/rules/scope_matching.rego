package rules

import rego.v1

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

matched_scopes(policy_nb) := { scope |
	some scope in scopes_eq(policy_nb) | scopes_path(policy_nb) | scopes_regexp(policy_nb)
}