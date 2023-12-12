package server_rules

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

default allowed_scopes_eq := false

default allowed_scopes_path := false

default allowed_scopes_regexp := false

default allowed_actor := false

scopes := split(input.scopes, " ")

allowed_scopes_eq if {
	some data_scope in data.scopes
	some input_scope in scopes
	data_scope == input_scope
}

allowed_scopes_path if {
	path_scopes = concat("* ", data.scopes)
	splitted_scopes = split(path_scopes, " ")
	some splitted_scope in splitted_scopes
	some scope in scopes
	glob.match(splitted_scope, [], scope)
}

allowed_scopes_regexp if {
	some scope in scopes
	glob.match("wlcg.groups:*", [], scope)
}

allowed_actor if {
	input.id == data.actor.id
	data.rule == "PERMIT"
}

## List of policies

allow if {
	allowed_actor
	data.matchingPolicy == "EQ"
	allowed_scopes_eq
}

allow if {
	allowed_actor
	data.matchingPolicy == "PATH"
	allowed_scopes_path
}

allow if {
	allowed_actor
	data.matchingPolicy == "REGEXP"
	allowed_scopes_regexp
}
