# FATF Recommendation 16 travel-rule thresholds (USD-equivalent) and the
# restricted-jurisdiction set, consumed by jurisdiction.rego as `data.fatf`.
# Mirrors aegis/config.py so the Rego bundle and the reference build agree.

package fatf

travel_rule_threshold := {
	"default": 1000,
	"US": 3000,
	"EU": 1000,
	"GB": 1000,
	"SG": 1000,
	"JP": 1000,
	"CH": 1000,
	"AE": 1000,
}

restricted_jurisdictions := {"IR", "KP", "SY", "CU"}
