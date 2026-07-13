import {
  transitionCampaign,
  type CampaignGuardContext,
} from "../../../packages/control-plane/campaign-machine.js";
import { describe, expect, it } from "vitest";
import {
  campaign,
  NOW,
  POLICY_HASH,
} from "../../fixtures/control-plane.factory.js";

const accepted: CampaignGuardContext = Object.freeze({
  acceptedPolicyVersion: 1,
  acceptedPolicyHash: POLICY_HASH,
  policyAssets: Object.freeze(["demo.local.test"]),
  configurationValid: true,
  killSwitchActive: false,
  externalActionRequested: false,
  externalIntegrationsEnabled: false,
  now: NOW,
});

describe("campaign state machine", () => {
  it("requires explicit policy and campaign approval before simulation", () => {
    const draft = campaign();
    const awaiting = transitionCampaign(
      draft,
      { kind: "request_approval" },
      accepted,
    );
    expect(awaiting.state).toBe("awaiting_campaign_approval");
    const approved = transitionCampaign(
      awaiting,
      { kind: "approve", actor: "local-reviewer", at: NOW },
      accepted,
    );
    const running = transitionCampaign(
      approved,
      { kind: "start_simulation" },
      accepted,
    );
    expect(running.state).toBe("running_simulation");
    expect(running.humanApprovedBy).toBe("local-reviewer");
  });

  it("waits for a missing acceptance", () => {
    const missing = { ...accepted, acceptedPolicyVersion: null };
    const waiting = transitionCampaign(
      campaign(),
      { kind: "request_approval" },
      missing,
    );
    expect(waiting.state).toBe("awaiting_policy_acceptance");
    expect(() =>
      transitionCampaign(waiting, { kind: "policy_accepted" }, missing),
    ).toThrow("CAMPAIGN_POLICY_NOT_ACCEPTED");
  });

  it.each([
    [
      "wrong hash",
      { acceptedPolicyHash: "f".repeat(64) },
      "CAMPAIGN_POLICY_HASH_MISMATCH",
    ],
    ["unknown asset", { policyAssets: [] }, "CAMPAIGN_ASSET_UNKNOWN"],
    [
      "invalid config",
      { configurationValid: false },
      "CAMPAIGN_CONFIG_INVALID",
    ],
    ["kill switch", { killSwitchActive: true }, "CAMPAIGN_KILL_SWITCH"],
    [
      "external disabled",
      { externalActionRequested: true },
      "EXTERNAL_INTEGRATIONS_DISABLED",
    ],
  ])("blocks start for %s", (_label, patch, code) => {
    const approved = campaign({
      state: "approved",
      revision: 2,
      humanApprovedBy: "local-reviewer",
      humanApprovedAt: NOW,
    });
    expect(() =>
      transitionCampaign(
        approved,
        { kind: "start_simulation" },
        { ...accepted, ...patch },
      ),
    ).toThrow(code);
  });

  it("pauses immediately on drift and requires a fresh campaign approval", () => {
    const running = campaign({ state: "running_simulation", revision: 3 });
    const paused = transitionCampaign(
      running,
      { kind: "policy_drift", at: NOW },
      accepted,
    );
    expect(paused.state).toBe("paused");
    expect(paused.humanApprovedBy).toBeNull();
    expect(paused.humanApprovedAt).toBeNull();
    const awaiting = transitionCampaign(
      paused,
      { kind: "resume_requested" },
      accepted,
    );
    expect(awaiting.state).toBe("awaiting_campaign_approval");
    expect(awaiting.humanApprovedBy).toBeNull();
  });

  it("blocks illegal transitions and invalid contracts", () => {
    expect(() =>
      transitionCampaign(campaign(), { kind: "start_simulation" }, accepted),
    ).toThrow("CAMPAIGN_TRANSITION_BLOCKED");
    const invalid = campaign({
      state: "approved",
      contract: { ...campaign().contract, writeActionsAllowed: true as false },
    });
    expect(() =>
      transitionCampaign(invalid, { kind: "start_simulation" }, accepted),
    ).toThrow("CAMPAIGN_CONTRACT_INVALID");
    const invalidDate = campaign({
      state: "approved",
      contract: {
        ...campaign().contract,
        validFrom: "not-a-time",
        validUntil: "also-not-a-time",
      },
    });
    expect(() =>
      transitionCampaign(invalidDate, { kind: "start_simulation" }, accepted),
    ).toThrow("CAMPAIGN_CONTRACT_INVALID");
    const missingCheckpoint = campaign({
      state: "approved",
      contract: {
        ...campaign().contract,
        humanCheckpoints: ["campaign_approval"],
      },
    });
    expect(() =>
      transitionCampaign(
        missingCheckpoint,
        { kind: "start_simulation" },
        accepted,
      ),
    ).toThrow("CAMPAIGN_CONTRACT_INVALID");
    const extraHost = campaign({
      state: "approved",
      contract: {
        ...campaign().contract,
        allowedHosts: ["demo.local.test", "unapproved.test"],
      },
    });
    expect(() =>
      transitionCampaign(extraHost, { kind: "start_simulation" }, accepted),
    ).toThrow("CAMPAIGN_CONTRACT_INVALID");
  });

  it("treats an unknown kill-switch value as engaged", () => {
    const approved = campaign({
      state: "approved",
      revision: 2,
      humanApprovedBy: "local-reviewer",
      humanApprovedAt: NOW,
    });
    for (const value of [undefined, null, 0, "false"]) {
      expect(() =>
        transitionCampaign(
          approved,
          { kind: "start_simulation" },
          {
            ...accepted,
            killSwitchActive: value as unknown as boolean,
          },
        ),
      ).toThrow("CAMPAIGN_KILL_SWITCH");
    }
  });

  it("rejects unknown external-integration booleans as invalid configuration", () => {
    const approved = campaign({
      state: "approved",
      revision: 2,
      humanApprovedBy: "local-reviewer",
      humanApprovedAt: NOW,
    });
    for (const field of [
      "externalActionRequested",
      "externalIntegrationsEnabled",
    ] as const)
      for (const value of [undefined, null, 0, "false"]) {
        expect(() =>
          transitionCampaign(
            approved,
            { kind: "start_simulation" },
            {
              ...accepted,
              [field]: value as unknown as boolean,
            },
          ),
        ).toThrow("CAMPAIGN_CONFIG_INVALID");
      }
  });

  it("supports an explicit safety block before cancellation", () => {
    const blocked = transitionCampaign(campaign(), { kind: "block" }, accepted);
    expect(blocked).toMatchObject({
      state: "blocked",
      humanApprovedBy: null,
      humanApprovedAt: null,
    });
    expect(
      transitionCampaign(blocked, { kind: "cancel" }, accepted).state,
    ).toBe("cancelled");
  });
});
