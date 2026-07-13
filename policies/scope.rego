package bugbounty.execution

import rego.v1

default allow := false

deny contains "policy hash changed" if {
  input.contract.policy_hash_sha256 != input.program.policy_hash_sha256
}

deny contains "contract expired" if {
  time.now_ns() > time.parse_rfc3339_ns(input.contract.valid_until)
}

deny contains "risk tier not approved" if {
  not input.candidate.risk_tier in input.contract.approved_risk_tiers
}

deny contains "asset not approved" if {
  not input.request.asset_ref in input.contract.asset_refs
}

deny contains "actor account not approved" if {
  not input.request.actor_account in input.contract.account_refs
}

deny contains "object not owned" if {
  some object_ref in input.candidate.owned_object_refs
  not input.ownership[object_ref].researcher_controlled
}

deny contains "request budget exceeded" if {
  input.runtime.candidate_request_count >= input.candidate.request_budget
}

deny contains "concurrency exceeded" if {
  input.runtime.active_requests >= input.contract.budgets.max_concurrency
}

deny contains "redirect requested" if {
  input.request.follow_redirects
}

deny contains "sensitive tier requires case approval" if {
  input.candidate.risk_tier == "tier_3_sensitive"
}

allow if count(deny) == 0
