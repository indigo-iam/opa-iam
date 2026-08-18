package rules

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default account_policy(_) := false
default group_policy(_) := false
default all_policy(_) := false

account_policy(policy_nb) if {
    data.policies[policy_nb].actor.type == "account"
}

account_policy(policy_nb) if {
    data.policies[policy_nb].account.uuid
    data.policies[policy_nb].group == null
}

# We want to consider a Client in the same way as an account,
# both for policy definition and policy evaluation order
account_policy(policy_nb) if {
    data.policies[policy_nb].actor.type == "client"
}

group_policy(policy_nb) if {
    data.policies[policy_nb].actor.type == "group"
}

group_policy(policy_nb) if {
    data.policies[policy_nb].group.uuid
    data.policies[policy_nb].account == null
}

all_policy(policy_nb) if {
    not data.policies[policy_nb].actor.type
} 

all_policy(policy_nb) if {
    data.policies[policy_nb].account == null
    data.policies[policy_nb].group == null
}