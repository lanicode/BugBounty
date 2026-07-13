import type { ProgramConfig } from "../../packages/config/types.js";
import type { TestContract } from "../../packages/policy/contract.js";

export function programConfig(
  overrides: { host?: string; port?: number; allowHttp?: boolean } = {},
): ProgramConfig {
  const host = overrides.host ?? "api.example.test";
  const port = overrides.port ?? 443;
  const allowHttp = overrides.allowHttp ?? false;
  return {
    version: 2,
    program: {
      platform: "local",
      handle: "authorized-test",
      display_name: "Local Test",
      policy_source: "fixture",
      policy_hash_sha256: "a".repeat(64),
      policy_accepted_at: "2026-01-01T00:00:00Z",
      policy_accepted_by: "tester",
    },
    network: {
      targets: [
        {
          scheme: allowHttp ? "http" : "https",
          host,
          ports: [port],
          path_prefixes: ["/api/"],
        },
      ],
      supporting_hosts: [
        {
          scheme: "https",
          host: "cdn.example.test",
          ports: [443],
          allowed_methods: ["GET"],
          capture: "metadata_only",
        },
      ],
      blocked_hosts: ["blocked.example.test"],
      deny_by_default: true,
      allow_plain_http: allowHttp,
      follow_redirects: false,
      block_service_workers_during_capture: true,
    },
    capture: {
      persist_unredacted_traffic: false,
      persist_response_bodies: "selective",
      allowed_body_content_types: ["application/json", "text/plain"],
      max_body_bytes: 1024,
      binary_handling: "hash_only",
      websocket_capture: "disabled",
      stable_pseudonyms: true,
      local_hmac_key_ref: "keychain://test/pseudonym",
      quarantine_unknown_identity_data: true,
    },
    accounts: [
      {
        id: "account-a",
        role: "owner",
        secret_ref: "keychain://test/a",
        email_alias_ref: "keychain://test/a-email",
      },
      {
        id: "account-b",
        role: "outsider",
        secret_ref: "keychain://test/b",
        email_alias_ref: "keychain://test/b-email",
      },
    ],
    budgets: {
      global_requests_per_minute: 3,
      max_concurrency: 1,
      max_requests_per_candidate: 3,
      max_state_changes_per_candidate: 0,
      stop_after_first_positive_signal: true,
      cool_down_seconds_after_error: 30,
      stop_statuses: [429, 503],
    },
    forbidden: ["active_testing"],
    policy_drift: {
      block_campaign_when_policy_hash_changes: true,
      require_new_acceptance: true,
    },
  };
}

export function contract(overrides: Partial<TestContract> = {}): TestContract {
  return {
    contract_id: "contract-1",
    program_handle: "authorized-test",
    policy_hash_sha256: "a".repeat(64),
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2027-01-01T00:00:00Z",
    approved_risk_tiers: ["tier_0_offline"],
    account_refs: ["account-a", "account-b"],
    asset_refs: ["asset-a"],
    budgets: {
      requests_per_minute: 3,
      max_concurrency: 1,
      max_requests_total: 3,
    },
    stop_conditions: ["unknown_identity"],
    approved_by: "tester",
    signature: "offline-signature",
    ...overrides,
  };
}
