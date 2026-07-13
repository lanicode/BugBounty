import { ApprovalQueue } from "../../../packages/control-plane/approval-queue.js";
import { describe, expect, it } from "vitest";
import { NOW, POLICY_HASH } from "../../fixtures/control-plane.factory.js";

function queueWithOpenItem(): { queue: ApprovalQueue; hash: string } {
  const queue = new ApprovalQueue();
  const item = queue.enqueue({
    id: "approval-1",
    kind: "campaign_contract",
    summary: "Approve local simulation contract",
    technicalDetails: "Tier 0; local mock only",
    impact: "Permits an in-process simulation",
    policyVersion: 1,
    policyHash: POLICY_HASH,
    createdAt: NOW,
    auditReference: "audit:approval-1",
  });
  return { queue, hash: item.payloadHash };
}

describe("ApprovalQueue", () => {
  it("requires an explicit, integrity-bound human decision", () => {
    const { queue, hash } = queueWithOpenItem();
    const decided = queue.decide({
      id: "approval-1",
      expectedRevision: 0,
      expectedPayloadHash: hash,
      decision: "accepted",
      actor: "local-reviewer",
      userAction: "clicked_accept",
      at: NOW,
      killSwitchActive: false,
    });
    expect(decided.status).toBe("accepted");
    expect(decided.revision).toBe(1);
  });

  it("blocks tampering, duplicate processing, and the kill switch", () => {
    const first = queueWithOpenItem();
    expect(() =>
      first.queue.decide({
        id: "approval-1",
        expectedRevision: 0,
        expectedPayloadHash: "0".repeat(64),
        decision: "accepted",
        actor: "local-reviewer",
        userAction: "clicked_accept",
        at: NOW,
        killSwitchActive: false,
      }),
    ).toThrow("APPROVAL_INTEGRITY_INVALID");
    first.queue.decide({
      id: "approval-1",
      expectedRevision: 0,
      expectedPayloadHash: first.hash,
      decision: "rejected",
      actor: "local-reviewer",
      userAction: "clicked_reject",
      at: NOW,
      killSwitchActive: false,
    });
    expect(() =>
      first.queue.decide({
        id: "approval-1",
        expectedRevision: 0,
        expectedPayloadHash: first.hash,
        decision: "accepted",
        actor: "local-reviewer",
        userAction: "clicked_accept",
        at: NOW,
        killSwitchActive: false,
      }),
    ).toThrow("APPROVAL_ALREADY_PROCESSED");

    const killed = queueWithOpenItem();
    expect(() =>
      killed.queue.decide({
        id: "approval-1",
        expectedRevision: 0,
        expectedPayloadHash: killed.hash,
        decision: "accepted",
        actor: "local-reviewer",
        userAction: "clicked_accept",
        at: NOW,
        killSwitchActive: true,
      }),
    ).toThrow("APPROVAL_KILL_SWITCH");
  });
});
