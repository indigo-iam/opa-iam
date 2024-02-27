package rules

import rego.v1

denied_scopes contains scope if {
	some scope in input.scopes
	scope_permission(scope) == "DENY"
}

filtered_scopes contains scope if {
	some scope in input.scopes
	scope_permission(scope) == "PERMIT"
}
