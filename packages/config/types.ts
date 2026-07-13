export interface NetworkTarget {
  readonly scheme: "http" | "https";
  readonly host: string;
  readonly ports: readonly number[];
  readonly path_prefixes: readonly string[];
}

export interface SupportingHost {
  readonly scheme: "http" | "https";
  readonly host: string;
  readonly ports: readonly number[];
  readonly allowed_methods: readonly ("GET" | "HEAD" | "OPTIONS" | "POST")[];
  readonly capture: "metadata_only" | "none";
}

export interface ProgramConfig {
  readonly version: 2;
  readonly program: {
    readonly platform: string;
    readonly handle: string;
    readonly display_name: string;
    readonly policy_source: string;
    readonly policy_hash_sha256: string;
    readonly policy_accepted_at: string | null;
    readonly policy_accepted_by: string | null;
  };
  readonly network: {
    readonly targets: readonly NetworkTarget[];
    readonly supporting_hosts: readonly SupportingHost[];
    readonly blocked_hosts?: readonly string[];
    readonly deny_by_default: true;
    readonly allow_plain_http: boolean;
    readonly follow_redirects: false;
    readonly block_service_workers_during_capture: true;
  };
  readonly capture: {
    readonly persist_unredacted_traffic: false;
    readonly persist_response_bodies: "selective";
    readonly allowed_body_content_types: readonly string[];
    readonly max_body_bytes: number;
    readonly binary_handling: "hash_only";
    readonly websocket_capture: string;
    readonly stable_pseudonyms: true;
    readonly local_hmac_key_ref: string;
    readonly quarantine_unknown_identity_data: true;
  };
  readonly accounts: readonly {
    readonly id: string;
    readonly role: string;
    readonly secret_ref: string;
    readonly email_alias_ref: string;
  }[];
  readonly budgets: {
    readonly global_requests_per_minute: number;
    readonly max_concurrency: 1;
    readonly max_requests_per_candidate: number;
    readonly max_state_changes_per_candidate: number;
    readonly stop_after_first_positive_signal: true;
    readonly cool_down_seconds_after_error: number;
    readonly stop_statuses: readonly number[];
  };
  readonly forbidden: readonly string[];
  readonly policy_drift: {
    readonly block_campaign_when_policy_hash_changes: true;
    readonly require_new_acceptance: true;
  };
}

export interface ValidatedConfig {
  readonly config: ProgramConfig;
  readonly canonical: string;
  readonly hash: string;
  readonly startable: boolean;
  readonly blockers: readonly string[];
}
