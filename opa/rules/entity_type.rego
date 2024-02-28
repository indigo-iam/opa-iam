package rules

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default subject_policy(_) := false
default group_policy(_) := false
default all_policy(_) := false

subject_policy(policy_nb) if {
    data.policies[policy_nb].actor.type == "subject"
}

subject_policy(policy_nb) if {
    data.policies[policy_nb].account.uuid
    data.policies[policy_nb].group == null
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