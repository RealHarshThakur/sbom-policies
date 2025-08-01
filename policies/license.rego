package license

import rego.v1

prohibited_licenses := ["AGPL-3.0-only", "MIT"]

review_licenses := ["GPL-2.0-only AND GPL-2.0-or-later AND MPL-2.0"]

deny contains msg if {
	pkg := input.packages[_]
	license := pkg.licenseConcluded
	pl := prohibited_licenses[_]
	license == pl
	msg = {"prohibited_license": license, "package": pkg.name}
}

warn contains msg if {
	pkg := input.packages[_]
	license := pkg.licenseConcluded
	rl := review_licenses[_]
	license == rl
	msg = {"review_license": license, "package": pkg.name}
}
