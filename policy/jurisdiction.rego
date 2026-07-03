# Feature 1 — Jurisdiction-Aware Mandate Firewall (conflict-of-laws resolver).
#
# In production this Rego bundle is the deterministic authority evaluated by OPA;
# `aegis/pipeline/f1_jurisdiction.py` mirrors it for the standalone reference
# build. The bundle is version-pinned (see bundle.manifest) so `ruleset_version`
# in every decision envelope resolves to an exact policy revision.

package aegis.jurisdiction

import future.keywords.if
import future.keywords.in

# Strictest-binding threshold across all touched jurisdictions.
applicable_travel_rule_threshold := t if {
	thresholds := [x |
		some j in input.touched_jurisdictions
		x := object.get(data.fatf.travel_rule_threshold, j.iso, data.fatf.travel_rule_threshold.default)
	]
	t := min(thresholds)
}

deny[reason] if {
	input.amount.value_usd >= applicable_travel_rule_threshold
	not travel_rule_fields_present
	reason := {
		"code": "AGENT.JUR.TRAVELRULE_MISSING",
		"detail": sprintf(
			"Transfer of %.2f USD >= threshold %.2f; originator/beneficiary attestation absent",
			[input.amount.value_usd, applicable_travel_rule_threshold],
		),
	}
}

deny[reason] if {
	input.buyer.residency == "EU"
	input.processing_region != "EU"
	reason := {"code": "AGENT.JUR.DATA_RESIDENCY", "detail": "EU PII processed outside EU enclave"}
}

deny[reason] if {
	some j in input.touched_jurisdictions
	j.iso in data.fatf.restricted_jurisdictions
	reason := {"code": "AGENT.JUR.RAIL_INELIGIBLE", "detail": sprintf("Corridor touches restricted jurisdiction %s", [j.iso])}
}

travel_rule_fields_present if {
	input.mandate.originator.legal_name
	input.mandate.originator.account_ref
	input.mandate.beneficiary.legal_name
}
