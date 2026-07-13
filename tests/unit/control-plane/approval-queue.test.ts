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

  it("hydrates persisted approvals only when their payload remains intact", () => {
    const source = queueWithOpenItem();
    const open = source.queue.get("approval-1");
    expect(open).toBeDefined();
    const hydrated = new ApprovalQueue(open === undefined ? [] : [open]);
    expect(
      hydrated.decide({
        id: "approval-1",
        expectedRevision: 0,
        expectedPayloadHash: source.hash,
        decision: "accepted",
        actor: "local-reviewer",
        userAction: "persisted_click_accept",
        at: NOW,
        killSwitchActive: false,
      }).status,
    ).toBe("accepted");
    expect(
      () =>
        new ApprovalQueue(
          open === undefined
            ? []
            : [{ ...open, summary: "tampered persisted summary" }],
        ),
    ).toThrow("APPROVAL_INTEGRITY_INVALID");
    expect(
      () =>
        new ApprovalQueue(
          open === undefined
            ? []
            : [
                {
                  ...open,
                  status: "accepted",
                  decidedAt: "2026-07-13T11:00:00.000Z",
                  decidedBy: "local-reviewer",
                  userAction: "clicked_accept",
                  revision: 1,
                },
              ],
        ),
    ).toThrow("APPROVAL_INTEGRITY_INVALID");
  });

  it("rejects secret-like material in approval text", () => {
    const queue = new ApprovalQueue();
    expect(() =>
      queue.enqueue({
        id: "approval-sensitive",
        kind: "privacy_alert",
        summary: "accidental pass".concat("word=placeholder-value"),
        technicalDetails: "Local test",
        impact: "Blocked",
        policyVersion: null,
        policyHash: null,
        createdAt: NOW,
        auditReference: "audit:approval-sensitive",
      }),
    ).toThrow("APPROVAL_SENSITIVE_MATERIAL");
  });

  it("rejects non-boolean kill state, invalid decisions, backdating, and secret user actions", () => {
    for (const killSwitchActive of [undefined, null, 0, "false"]) {
      const { queue, hash } = queueWithOpenItem();
      expect(() =>
        queue.decide({
          id: "approval-1",
          expectedRevision: 0,
          expectedPayloadHash: hash,
          decision: "accepted",
          actor: "local-reviewer",
          userAction: "clicked_accept",
          at: NOW,
          killSwitchActive: killSwitchActive as unknown as boolean,
        }),
      ).toThrow("APPROVAL_KILL_SWITCH");
    }

    const invalidDecision = queueWithOpenItem();
    expect(() =>
      invalidDecision.queue.decide({
        id: "approval-1",
        expectedRevision: 0,
        expectedPayloadHash: invalidDecision.hash,
        decision: "approved" as "accepted",
        actor: "local-reviewer",
        userAction: "clicked_accept",
        at: NOW,
        killSwitchActive: false,
      }),
    ).toThrow("APPROVAL_DECISION_INVALID");

    const backdated = queueWithOpenItem();
    expect(() =>
      backdated.queue.decide({
        id: "approval-1",
        expectedRevision: 0,
        expectedPayloadHash: backdated.hash,
        decision: "accepted",
        actor: "local-reviewer",
        userAction: "clicked_accept",
        at: "2026-07-13T11:59:59.000Z",
        killSwitchActive: false,
      }),
    ).toThrow("APPROVAL_DECISION_INVALID");

    const sensitive = queueWithOpenItem();
    expect(() =>
      sensitive.queue.decide({
        id: "approval-1",
        expectedRevision: 0,
        expectedPayloadHash: sensitive.hash,
        decision: "accepted",
        actor: "local-reviewer",
        userAction: "Cookie: sid=".concat("local-session-value"),
        at: NOW,
        killSwitchActive: false,
      }),
    ).toThrow("APPROVAL_SENSITIVE_MATERIAL");
  });
});
