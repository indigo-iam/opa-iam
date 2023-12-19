package server_rules

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

default allowed_scopes_eq := false

default allowed_scopes_path := false

default allowed_scopes_regexp := false

default matched_actor := false

matched_actor := nb if {
	some nb 
	input.id == data.policies[nb].actor.id
	data.policies[nb].rule == "PERMIT"
}

matcher_actor := nb if {
	# IAM policy definition based on group uuid
	some nb
	input.id == data.policies[nb].group.uuid
	data.policies[nb].rule == "PERMIT"
}

matched_actor := nb if {
	# IAM policy definition based on user uuid
	some nb
	input.id == data.policies[nb].acount.uuid
	data.policies[nb].rule == "PERMIT"
}

input_list_scopes := split(input.scopes, " ")

allowed_scopes_eq if {
	data.policies[matched_actor].scopes[_] == input_list_scopes[_]
}

allowed_scopes_path if {
	path_scopes = concat("", [concat("* ", data.policies[matched_actor].scopes), "*"])
	splitted_scopes = split(path_scopes, " ") 
	allowed_scopes = glob.match(splitted_scopes[_], [], input_list_scopes[_])
}

allowed_scopes_regexp if {
	glob.match("wlcg.groups:*", [], input_list_scopes[_])
}

## List of policies

allow if {
	matched_actor
	some allowed_actor
	data.policies[allowed_actor].matchingPolicy == "EQ"
	allowed_scopes_eq
}

allow if {
	matched_actor
	some allowed_actor
	data.policies[allowed_actor].matchingPolicy == "PATH"
	allowed_scopes_path
}

allow if {
	matched_actor
	some allowed_actor
	data.policies[allowed_actor].matchingPolicy == "REGEXP"
	allowed_scopes_regexp
}
