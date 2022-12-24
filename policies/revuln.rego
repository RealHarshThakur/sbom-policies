package vuln

import future.keywords

# TODO: 
## * Mention if vulnerability has a fix available

allow_list := ["CVE-2015-5237"]
vuln_level := ["High", "Medium"]

deny[msg] {
  vuln_level[_] = level
  ids := parse_vuln_ids(level)
  ids = filter_allow_list(allow_list, ids)
  msg := {level: ids}
}

filter_allow_list(allow_list, ids) = result {
  result := [id | id = ids[_]; not id in allow_list]
}

parse_vuln_ids(level):= ids if {
    ids := [id | 
    input.matches[i].vulnerability.severity == level
    id := input.matches[i].vulnerability.id]
}
