import fc from "fast-check";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ControlPlaneDatabase,
  type ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  DeterministicMockActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
  StoreBoundExternalActionEvaluator,
  type ExternalActionProposal,
} from "../../packages/external-actions/index.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
} from "../../packages/phase2-config/index.js";
import { sha256 } from "../../packages/shared/canonical.js";
import { SecurityError } from "../../packages/shared/errors.js";
import {
  ACTION_EXECUTION_TIME,
  ACTION_TIME,
  seedStoreBoundAction,
} from "../fixtures/store-bound-action.factory.js";

const MUTABLE_PROPOSAL_FIELDS = [
  "account_ref",
  "account_role",
  "action_id",
  "approval_ref",
  "campaign_digest",
  "campaign_ref",
  "campaign_revision",
  "mode",
  "object_ref",
  "operator_ref",
  "payload_ref",
  "policy_hash_sha256",
  "policy_version",
  "program_ref",
  "proposal_id",
  "scope_ref",
] as const;

const IMMUTABLE_BINDING_FIELDS = [
  "action_id",
  "binding_digest",
  "campaign_digest",
  "campaign_revision",
  "object_ref",
  "operator_id",
  "policy_hash",
  "policy_version",
  "proposal_digest",
  "proposal_id",
  "scope_ref",
] as const;

function runtime() {
  return resolvePhase2Runtime(SAFE_PHASE2_CONFIG, {
    secretsAvailable: false,
    externalAdapterAvailable: false,
  });
}

function pipeline(
  store: ControlPlaneStore,
  runner: DeterministicMockActionRunner,
): ExternalActionPipeline {
  return new ExternalActionPipeline(
    runtime(),
    runner,
    new Phase2KillSwitch({ readActive: () => store.isKillSwitchActive() }),
    new StoreBoundExternalActionEvaluator(store),
  );
}

describe("store-bound evaluator properties", () => {
  let database: ControlPlaneDatabase;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(ACTION_TIME);
    database = ControlPlaneDatabase.memory();
  });

  afterEach(() => {
    database.close();
    vi.useRealTimers();
  });

  it("blocks every generated proposal-field mutation before the runner", async () => {
    const seeded = seedStoreBoundAction(database, "target_request");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    const evaluator = pipeline(seeded.store, runner);

    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...MUTABLE_PROPOSAL_FIELDS),
        fc.stringMatching(/^[A-Za-z][A-Za-z0-9_-]{0,31}$/u),
        async (field, nonce) => {
          const mutated = mutateProposal(seeded.proposal, field, nonce);
          await expect(evaluator.execute(mutated)).rejects.toBeInstanceOf(
            SecurityError,
          );
          expect(runner.recordedExecutions()).toHaveLength(0);
          expect(seeded.store.listExternalActionAttempts()).toHaveLength(0);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("rejects every generated write to an immutable approval binding", () => {
    seedStoreBoundAction(database, "target_request");

    fc.assert(
      fc.property(fc.constantFrom(...IMMUTABLE_BINDING_FIELDS), (field) => {
        expect(() =>
          database.run(
            `UPDATE external_action_approval_bindings SET ${field}=${field} WHERE approval_id='action-approval-1'`,
          ),
        ).toThrow("EXTERNAL_ACTION_APPROVAL_BINDING_IMMUTABLE");
      }),
      { numRuns: 100 },
    );
  });
});

function mutateProposal(
  proposal: ExternalActionProposal,
  field: (typeof MUTABLE_PROPOSAL_FIELDS)[number],
  nonce: string,
): unknown {
  const reference = `changed-${sha256(nonce).slice(0, 24)}`;
  switch (field) {
    case "proposal_id":
      return { ...proposal, proposal_id: reference };
    case "action_id":
      return { ...proposal, action_id: "platform_api_read" };
    case "mode":
      return { ...proposal, mode: "external" };
    case "program_ref":
    case "campaign_ref":
    case "scope_ref":
    case "account_ref":
    case "object_ref":
    case "approval_ref":
      return {
        ...proposal,
        parameters: { ...proposal.parameters, [field]: reference },
      };
    case "operator_ref":
      return {
        ...proposal,
        parameters: {
          ...proposal.parameters,
          operator_ref: `reviewer-${reference}`,
        },
      };
    case "campaign_revision":
      return {
        ...proposal,
        parameters: {
          ...proposal.parameters,
          campaign_revision: proposal.parameters.campaign_revision + 1,
        },
      };
    case "policy_version":
      return {
        ...proposal,
        parameters: {
          ...proposal.parameters,
          policy_version: proposal.parameters.policy_version + 1,
        },
      };
    case "campaign_digest":
    case "policy_hash_sha256":
      return {
        ...proposal,
        parameters: { ...proposal.parameters, [field]: sha256(reference) },
      };
    case "account_role":
      return {
        ...proposal,
        parameters: { ...proposal.parameters, account_role: "Member" },
      };
    case "payload_ref":
      return {
        ...proposal,
        parameters: { ...proposal.parameters, payload_ref: reference },
      };
  }
}
