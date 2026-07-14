import { describe, expect, it } from "vitest";
import {
  externalActionProposalDigest,
  validateAndFreezeExternalActionProposal,
  type ExternalActionProposalV2,
} from "../../packages/external-actions/proposal.js";

function proposal(): ExternalActionProposalV2 {
  return {
    version: 2,
    proposal_id: "proposal-1",
    action_id: "target_request",
    mode: "simulation",
    parameters: {
      program_ref: "program-local",
      campaign_ref: "campaign-local",
      campaign_revision: 3,
      campaign_digest: "a".repeat(64),
      policy_version: 1,
      policy_hash_sha256: "b".repeat(64),
      scope_ref: "scope-local",
      account_ref: "identity-owner",
      account_role: "Owner",
      object_ref: "object-local",
      payload_ref: null,
      approval_ref: "approval-local",
      operator_ref: "local-reviewer@example.test",
    },
  };
}

describe("Phase 3 external action proposal contract", () => {
  it("validates the exact v2 schema and returns a detached deep-frozen value", () => {
    const input = proposal();
    const validated = validateAndFreezeExternalActionProposal(input);

    expect(validated).toEqual(input);
    expect(Object.isFrozen(validated)).toBe(true);
    expect(Object.isFrozen(validated.parameters)).toBe(true);

    (input as { proposal_id: string }).proposal_id = "mutated-input";
    (input.parameters as { scope_ref: string }).scope_ref = "mutated-scope";
    expect(validated.proposal_id).toBe("proposal-1");
    expect(validated.parameters.scope_ref).toBe("scope-local");
    expect(() => {
      (
        validated.parameters as { campaign_revision: number }
      ).campaign_revision = 4;
    }).toThrow(TypeError);
  });

  it("binds the digest to every security-relevant proposal field", () => {
    const baseline = proposal();
    const baselineDigest = externalActionProposalDigest(baseline);
    expect(baselineDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(externalActionProposalDigest({ ...proposal() })).toBe(
      baselineDigest,
    );

    const mutations: readonly ExternalActionProposalV2[] = [
      { ...proposal(), proposal_id: "proposal-2" },
      { ...proposal(), action_id: "browser_journey_start" },
      { ...proposal(), mode: "external" },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, program_ref: "program-other" },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          campaign_ref: "campaign-other",
        },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, campaign_revision: 4 },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          campaign_digest: "c".repeat(64),
        },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, policy_version: 2 },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          policy_hash_sha256: "d".repeat(64),
        },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, scope_ref: "scope-other" },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          account_ref: "identity-member",
        },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, account_role: "Member" },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, object_ref: "object-other" },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, payload_ref: "payload-local" },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          approval_ref: "approval-other",
        },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          operator_ref: "other-reviewer",
        },
      },
    ];
    for (const mutation of mutations)
      expect(externalActionProposalDigest(mutation)).not.toBe(baselineDigest);
  });

  it("rejects accessors without invoking them and rejects proxies", () => {
    let getterCalls = 0;
    const accessor = Object.defineProperty(proposal(), "proposal_id", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "proposal-accessor";
      },
    });
    expect(() => validateAndFreezeExternalActionProposal(accessor)).toThrow(
      "ACTION_PROPOSAL_INVALID",
    );
    expect(getterCalls).toBe(0);

    const nestedAccessor = Object.defineProperty(
      proposal().parameters,
      "operator_ref",
      {
        enumerable: true,
        get: () => {
          getterCalls += 1;
          return "accessor-reviewer";
        },
      },
    );
    expect(() =>
      validateAndFreezeExternalActionProposal({
        ...proposal(),
        parameters: nestedAccessor,
      }),
    ).toThrow("ACTION_PROPOSAL_INVALID");
    expect(getterCalls).toBe(0);

    expect(() =>
      validateAndFreezeExternalActionProposal(new Proxy(proposal(), {})),
    ).toThrow("ACTION_PROPOSAL_INVALID");
    expect(() =>
      validateAndFreezeExternalActionProposal({
        ...proposal(),
        parameters: new Proxy(proposal().parameters, {}),
      }),
    ).toThrow("ACTION_PROPOSAL_INVALID");
  });

  it("rejects v1, unsafe revisions, invalid actors and all extra fields", () => {
    const missingOperator: Record<string, unknown> = {
      ...proposal().parameters,
    };
    delete missingOperator["operator_ref"];
    const invalid: readonly unknown[] = [
      { ...proposal(), version: 1 },
      { ...proposal(), target_url: "http://127.0.0.1:9999" },
      { ...proposal(), required_secret_ref: "secret://forged" },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          target_url: "http://127.0.0.1:9999",
        },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          required_secret_ref: "secret://forged",
        },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, campaign_revision: -1 },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, campaign_revision: 1.5 },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          campaign_revision: Number.MAX_SAFE_INTEGER + 1,
        },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, operator_ref: "not an actor" },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, account_role: "Administrator" },
      },
      {
        ...proposal(),
        parameters: { ...proposal().parameters, policy_version: 0 },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          campaign_digest: "a".repeat(63),
        },
      },
      {
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          program_ref: "a".repeat(129),
        },
      },
      { ...proposal(), parameters: missingOperator },
    ];

    for (const candidate of invalid)
      expect(() => validateAndFreezeExternalActionProposal(candidate)).toThrow(
        "ACTION_PROPOSAL_INVALID",
      );
  });
});
