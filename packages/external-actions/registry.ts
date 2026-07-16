import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

export type ExternalActionId =
  | "browser_journey_start"
  | "email_verification_open"
  | "hackerone_active_test"
  | "hackerone_metadata_read"
  | "platform_api_read"
  | "report_submit"
  | "target_request"
  | "test_account_register"
  | "triage_response_send";

export type ExternalActionTargetClass =
  | "browser_journey"
  | "email_verification"
  | "hackerone_metadata"
  | "platform_api"
  | "program_target"
  | "report_submission"
  | "test_application"
  | "triage_response";

export type ExternalActionSecretKind =
  | "browser_profile"
  | "email_verification_capability"
  | "hackerone_api_credentials"
  | "platform_api_token"
  | "operator_signing_key"
  | "test_identity_credentials"
  | "test_identity_session";

export type ExternalActionHumanCheckpoint =
  | "campaign_approval"
  | "email_verification"
  | "hackerone_metadata_activation"
  | "signed_active_test_plan"
  | "manual_account_registration"
  | "not_required"
  | "report_collective_approval"
  | "triage_response_approval";

export interface ExternalActionDefinition {
  readonly actionId: ExternalActionId;
  readonly category:
    "account" | "browser" | "platform" | "report" | "target" | "triage";
  readonly triggerComponent: string;
  readonly targetClass: ExternalActionTargetClass;
  readonly fixedTargetPolicy:
    | {
        readonly kind: "external_disabled";
        readonly scheme: null;
        readonly host: null;
      }
    | {
        readonly kind: "registry_loopback_mock";
        readonly scheme: "http";
        readonly host: "127.0.0.1";
      }
    | {
        readonly kind: "hackerone_metadata_readonly";
        readonly scheme: "https";
        readonly host: "api.hackerone.com";
        readonly port: 443;
        readonly method: "GET";
      }
    | {
        readonly kind: "hackerone_active_test_exact_scope";
        readonly scheme: "https";
        readonly port: 443;
        readonly snapshotRequirement: "current_hackerone_api_authenticated";
        readonly scopeRequirement: "exact_selected_structured_scope";
        readonly ownershipRequirement: "selected_scope_asset_digest";
        readonly testClasses: readonly [
          {
            readonly id: "http_headers";
            readonly method: "HEAD";
          },
          {
            readonly id: "cors_preflight";
            readonly method: "OPTIONS";
          },
          {
            readonly id: "security_txt";
            readonly method: "GET";
          },
        ];
      };
  readonly requiredSecretKind: ExternalActionSecretKind;
  readonly policyDecision: "required";
  readonly scopeCheck: "required";
  readonly ownershipCheck: "account" | "not_applicable" | "object";
  readonly budget: {
    readonly kind: "action_units";
    readonly units: 1;
  };
  readonly humanCheckpoint: ExternalActionHumanCheckpoint;
  readonly defaultState: "blocked";
  readonly killSwitchBehavior: "block_before_and_after_runner";
  readonly simulationSupported: boolean;
}

const LOOPBACK_TARGET = Object.freeze({
  kind: "registry_loopback_mock" as const,
  scheme: "http" as const,
  host: "127.0.0.1" as const,
});

const DISABLED_TARGET = Object.freeze({
  kind: "external_disabled" as const,
  scheme: null,
  host: null,
});

const ACTION_BUDGET = Object.freeze({
  kind: "action_units" as const,
  units: 1 as const,
});

const HACKERONE_METADATA_TARGET = Object.freeze({
  kind: "hackerone_metadata_readonly" as const,
  scheme: "https" as const,
  host: "api.hackerone.com" as const,
  port: 443 as const,
  method: "GET" as const,
});

const HACKERONE_ACTIVE_TEST_CLASSES = Object.freeze([
  Object.freeze({ id: "http_headers" as const, method: "HEAD" as const }),
  Object.freeze({
    id: "cors_preflight" as const,
    method: "OPTIONS" as const,
  }),
  Object.freeze({ id: "security_txt" as const, method: "GET" as const }),
] as const);

const HACKERONE_ACTIVE_TEST_TARGET = Object.freeze({
  kind: "hackerone_active_test_exact_scope" as const,
  scheme: "https" as const,
  port: 443 as const,
  snapshotRequirement: "current_hackerone_api_authenticated" as const,
  scopeRequirement: "exact_selected_structured_scope" as const,
  ownershipRequirement: "selected_scope_asset_digest" as const,
  testClasses: HACKERONE_ACTIVE_TEST_CLASSES,
});

const trustedDefinitions = new WeakSet();

function define(
  value: Omit<
    ExternalActionDefinition,
    | "budget"
    | "defaultState"
    | "killSwitchBehavior"
    | "policyDecision"
    | "scopeCheck"
  >,
): ExternalActionDefinition {
  const definition = Object.freeze({
    ...value,
    budget: ACTION_BUDGET,
    defaultState: "blocked",
    killSwitchBehavior: "block_before_and_after_runner",
    policyDecision: "required",
    scopeCheck: "required",
  });
  trustedDefinitions.add(definition);
  return definition;
}

const REGISTRY: Readonly<Record<ExternalActionId, ExternalActionDefinition>> =
  Object.freeze({
    hackerone_active_test: define({
      actionId: "hackerone_active_test",
      category: "target",
      triggerComponent: "pilot_c_active_testing_gate",
      targetClass: "program_target",
      fixedTargetPolicy: HACKERONE_ACTIVE_TEST_TARGET,
      requiredSecretKind: "operator_signing_key",
      ownershipCheck: "object",
      humanCheckpoint: "signed_active_test_plan",
      simulationSupported: false,
    }),
    hackerone_metadata_read: define({
      actionId: "hackerone_metadata_read",
      category: "platform",
      triggerComponent: "hackerone_readonly_adapter",
      targetClass: "hackerone_metadata",
      fixedTargetPolicy: HACKERONE_METADATA_TARGET,
      requiredSecretKind: "hackerone_api_credentials",
      ownershipCheck: "not_applicable",
      humanCheckpoint: "hackerone_metadata_activation",
      simulationSupported: false,
    }),
    platform_api_read: define({
      actionId: "platform_api_read",
      category: "platform",
      triggerComponent: "platform_adapter",
      targetClass: "platform_api",
      fixedTargetPolicy: LOOPBACK_TARGET,
      requiredSecretKind: "platform_api_token",
      ownershipCheck: "not_applicable",
      humanCheckpoint: "not_required",
      simulationSupported: true,
    }),
    test_account_register: define({
      actionId: "test_account_register",
      category: "account",
      triggerComponent: "account_lifecycle",
      targetClass: "test_application",
      fixedTargetPolicy: LOOPBACK_TARGET,
      requiredSecretKind: "test_identity_credentials",
      ownershipCheck: "not_applicable",
      humanCheckpoint: "manual_account_registration",
      simulationSupported: true,
    }),
    email_verification_open: define({
      actionId: "email_verification_open",
      category: "account",
      triggerComponent: "account_lifecycle",
      targetClass: "email_verification",
      fixedTargetPolicy: LOOPBACK_TARGET,
      requiredSecretKind: "email_verification_capability",
      ownershipCheck: "account",
      humanCheckpoint: "email_verification",
      simulationSupported: true,
    }),
    browser_journey_start: define({
      actionId: "browser_journey_start",
      category: "browser",
      triggerComponent: "browser_orchestrator",
      targetClass: "browser_journey",
      fixedTargetPolicy: LOOPBACK_TARGET,
      requiredSecretKind: "browser_profile",
      ownershipCheck: "account",
      humanCheckpoint: "campaign_approval",
      simulationSupported: true,
    }),
    target_request: define({
      actionId: "target_request",
      category: "target",
      triggerComponent: "deterministic_test_runner",
      targetClass: "program_target",
      fixedTargetPolicy: LOOPBACK_TARGET,
      requiredSecretKind: "test_identity_session",
      ownershipCheck: "object",
      humanCheckpoint: "not_required",
      simulationSupported: true,
    }),
    report_submit: define({
      actionId: "report_submit",
      category: "report",
      triggerComponent: "reporting",
      targetClass: "report_submission",
      fixedTargetPolicy: DISABLED_TARGET,
      requiredSecretKind: "platform_api_token",
      ownershipCheck: "object",
      humanCheckpoint: "report_collective_approval",
      simulationSupported: false,
    }),
    triage_response_send: define({
      actionId: "triage_response_send",
      category: "triage",
      triggerComponent: "triage_workspace",
      targetClass: "triage_response",
      fixedTargetPolicy: DISABLED_TARGET,
      requiredSecretKind: "platform_api_token",
      ownershipCheck: "object",
      humanCheckpoint: "triage_response_approval",
      simulationSupported: false,
    }),
  });

const DEFINITIONS: readonly ExternalActionDefinition[] = Object.freeze([
  REGISTRY.hackerone_active_test,
  REGISTRY.hackerone_metadata_read,
  REGISTRY.platform_api_read,
  REGISTRY.test_account_register,
  REGISTRY.email_verification_open,
  REGISTRY.browser_journey_start,
  REGISTRY.target_request,
  REGISTRY.report_submit,
  REGISTRY.triage_response_send,
]);

export function getExternalActionDefinition(
  actionId: string,
): ExternalActionDefinition | undefined {
  switch (actionId) {
    case "hackerone_active_test":
      return REGISTRY.hackerone_active_test;
    case "hackerone_metadata_read":
      return REGISTRY.hackerone_metadata_read;
    case "platform_api_read":
      return REGISTRY.platform_api_read;
    case "test_account_register":
      return REGISTRY.test_account_register;
    case "email_verification_open":
      return REGISTRY.email_verification_open;
    case "browser_journey_start":
      return REGISTRY.browser_journey_start;
    case "target_request":
      return REGISTRY.target_request;
    case "report_submit":
      return REGISTRY.report_submit;
    case "triage_response_send":
      return REGISTRY.triage_response_send;
    default:
      return undefined;
  }
}

export function assertTrustedExternalActionDefinition(
  value: unknown,
  expectedActionId: ExternalActionId,
): asserts value is ExternalActionDefinition {
  const actionId =
    typeof value === "object" && value !== null
      ? Object.getOwnPropertyDescriptor(value, "actionId")
      : undefined;
  if (
    typeof value !== "object" ||
    value === null ||
    !Object.isFrozen(value) ||
    !trustedDefinitions.has(value) ||
    actionId === undefined ||
    !("value" in actionId) ||
    actionId.value !== expectedActionId
  )
    throw new SecurityError("ACTION_REGISTRY_DEFINITION_UNTRUSTED");
}

export function trustedExternalActionDefinitionDigest(
  actionId: ExternalActionId,
): string {
  const definition = getExternalActionDefinition(actionId);
  assertTrustedExternalActionDefinition(definition, actionId);
  return sha256(canonicalJson(definition));
}

export function hackerOneActiveTestRegistryDefinitionDigest(): string {
  const definition = getExternalActionDefinition("hackerone_active_test");
  assertTrustedExternalActionDefinition(definition, "hackerone_active_test");
  const digest = trustedExternalActionDefinitionDigest("hackerone_active_test");
  const expectedDigest = sha256(
    canonicalJson({
      actionId: "hackerone_active_test",
      category: "target",
      triggerComponent: "pilot_c_active_testing_gate",
      targetClass: "program_target",
      fixedTargetPolicy: HACKERONE_ACTIVE_TEST_TARGET,
      requiredSecretKind: "operator_signing_key",
      policyDecision: "required",
      scopeCheck: "required",
      ownershipCheck: "object",
      budget: ACTION_BUDGET,
      humanCheckpoint: "signed_active_test_plan",
      defaultState: "blocked",
      killSwitchBehavior: "block_before_and_after_runner",
      simulationSupported: false,
    }),
  );
  if (digest !== expectedDigest)
    throw new SecurityError("ACTIVE_TEST_ACTION_REGISTRY_INVALID");
  return digest;
}

export function assertHackerOneActiveTestRegistryPlanBinding(
  testClass: string,
  method: string,
  scheme: string,
  port: number,
): string {
  const digest = hackerOneActiveTestRegistryDefinitionDigest();
  const definition = getExternalActionDefinition("hackerone_active_test");
  assertTrustedExternalActionDefinition(definition, "hackerone_active_test");
  const target = definition.fixedTargetPolicy;
  if (
    target.kind !== "hackerone_active_test_exact_scope" ||
    scheme !== target.scheme ||
    port !== target.port ||
    !target.testClasses.some(
      (candidate) => candidate.id === testClass && candidate.method === method,
    )
  )
    throw new SecurityError("ACTIVE_TEST_ACTION_REGISTRY_PLAN_MISMATCH");
  return digest;
}

export function listExternalActionDefinitions(): readonly ExternalActionDefinition[] {
  return DEFINITIONS;
}
