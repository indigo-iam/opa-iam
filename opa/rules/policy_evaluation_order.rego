package rules

import future.keywords.if
import future.keywords.in
import future.keywords.contains

import data.rules.entity_matching as policy_nb

default scope_permission(_) := "PERMIT"

matched_policies_by_scope[scope] contains {"account": permission} if {
    some policy in policy_nb.matched_policy
    account_policy(policy)
    some scope in matched_scopes(policy)
    permission := data.policies[policy].rule
}

matched_policies_by_scope[scope] contains {"group": permission} if {
    some policy in policy_nb.matched_policy
    group_policy(policy)
    some scope in matched_scopes(policy)
    permission := data.policies[policy].rule
}

matched_policies_by_scope[scope] contains {"all": permission} if {
    some policy in policy_nb.matched_policy
    all_policy(policy)
    some scope in matched_scopes(policy)
    permission := data.policies[policy].rule
}

account_permission(scope) := "PERMIT" if {
    matched_policies_by_scope[scope][_].account == "PERMIT"
    matched_policies_by_scope[scope][_].account == "DENY"
} else := rule if {
    rule := matched_policies_by_scope[scope][_].account
}

group_permission(scope) := "PERMIT" if {
    matched_policies_by_scope[scope][_].group == "PERMIT"
    matched_policies_by_scope[scope][_].group == "DENY"
} else := rule if {
    rule := matched_policies_by_scope[scope][_].group
}

all_permission(scope) := "PERMIT" if {
    matched_policies_by_scope[scope][_].all == "PERMIT"
    matched_policies_by_scope[scope][_].all == "DENY"
} else := rule if {
    rule := matched_policies_by_scope[scope][_].all
}

scope_permission(scope) := rule if {
    rule := account_permission(scope)
} else := rule if {
    rule := group_permission(scope)
} else := rule if {
    rule := all_permission(scope)
}