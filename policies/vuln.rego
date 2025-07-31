package vuln

import rego.v1

# TODO:
# ONLY FLAG ON CRITICAL VULNERABILITY
## * Mention if vulnerability has a fix available

allow_list := ["CVE-2019-8457"]

vuln_level := ["High", "Medium", "Low"]

# vuln_level := ["Critical"]

deny contains msg if {
	vuln_level[_] = level
	ids := parse_vuln_ids(level)
	ids = filter_allow_list(allow_list, ids)
	msg := {level: ids}
}

filter_allow_list(allow_list, ids) := result if {
	result := [id | id = ids[_]; not id in allow_list]
}

parse_vuln_ids(level) := ids if {
	ids := [id |
		input.matches[i].vulnerability.severity == level
		id := input.matches[i].vulnerability.id
	]
}
