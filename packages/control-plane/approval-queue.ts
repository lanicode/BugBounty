import { canonicalJson, sha256, type JsonValue } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import type { ApprovalKind, ApprovalRecord } from "./types.js";
import { assertNoSensitiveMaterial } from "./sensitive.js";

export interface ApprovalInput {
  readonly id: string;
  readonly kind: ApprovalKind;
  readonly summary: string;
  readonly technicalDetails: string;
  readonly impact: string;
  readonly policyVersion: number | null;
  readonly policyHash: string | null;
  readonly createdAt: string;
  readonly auditReference: string;
}

export class ApprovalQueue {
  readonly #items = new Map<string, ApprovalRecord>();

  public constructor(initial: readonly ApprovalRecord[] = []) {
    for (const record of initial) {
      validateHydratedRecord(record);
      if (this.#items.has(record.id))
        throw new SecurityError("APPROVAL_ALREADY_EXISTS");
      this.#items.set(record.id, freeze({ ...record }));
    }
  }

  public enqueue(input: ApprovalInput): ApprovalRecord {
    validateInput(input);
    if (this.#items.has(input.id))
      throw new SecurityError("APPROVAL_ALREADY_EXISTS");
    const payloadHash = approvalHash(input);
    const record = freeze({
      ...input,
      status: "open" as const,
      decidedAt: null,
      decidedBy: null,
      userAction: null,
      payloadHash,
      revision: 0,
    });
    this.#items.set(input.id, record);
    return record;
  }

  public decide(input: {
    readonly id: string;
    readonly expectedRevision: number;
    readonly expectedPayloadHash: string;
    readonly decision: "accepted" | "rejected";
    readonly actor: string;
    readonly userAction: string;
    readonly at: string;
    readonly killSwitchActive: boolean;
  }): ApprovalRecord {
    const killSwitchActive: unknown = input.killSwitchActive;
    if (killSwitchActive !== false)
      throw new SecurityError("APPROVAL_KILL_SWITCH");
    const current = this.#items.get(input.id);
    if (current === undefined) throw new SecurityError("APPROVAL_NOT_FOUND");
    if (
      current.status !== "open" ||
      current.revision !== input.expectedRevision
    )
      throw new SecurityError("APPROVAL_ALREADY_PROCESSED");
    if (
      current.payloadHash !== input.expectedPayloadHash ||
      current.payloadHash !== approvalHash(current)
    )
      throw new SecurityError("APPROVAL_INTEGRITY_INVALID");
    const decision: unknown = input.decision;
    if (
      !/^[A-Za-z0-9._@-]{1,128}$/u.test(input.actor) ||
      (decision !== "accepted" && decision !== "rejected") ||
      !Number.isFinite(Date.parse(input.at)) ||
      Date.parse(input.at) < Date.parse(current.createdAt) ||
      input.userAction.trim().length === 0 ||
      input.userAction.length > 500
    )
      throw new SecurityError("APPROVAL_DECISION_INVALID");
    assertNoSensitiveMaterial(
      [input.userAction],
      "APPROVAL_SENSITIVE_MATERIAL",
    );
    const decided = freeze({
      ...current,
      status: decision,
      decidedAt: input.at,
      decidedBy: input.actor,
      userAction: input.userAction,
      revision: current.revision + 1,
    });
    this.#items.set(input.id, decided);
    return decided;
  }

  public get(id: string): ApprovalRecord | undefined {
    return this.#items.get(id);
  }

  public list(): readonly ApprovalRecord[] {
    return Object.freeze(
      [...this.#items.values()].sort((left, right) =>
        left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
      ),
    );
  }
}

function approvalHash(input: ApprovalInput | ApprovalRecord): string {
  const payload: JsonValue = {
    id: input.id,
    kind: input.kind,
    summary: input.summary,
    technicalDetails: input.technicalDetails,
    impact: input.impact,
    policyVersion: input.policyVersion,
    policyHash: input.policyHash,
    createdAt: input.createdAt,
    auditReference: input.auditReference,
  };
  return sha256(canonicalJson(payload));
}

function validateInput(input: ApprovalInput): void {
  assertNoSensitiveMaterial(
    [input.summary, input.technicalDetails, input.impact],
    "APPROVAL_SENSITIVE_MATERIAL",
  );
  if (
    !/^[A-Za-z0-9_-]{1,128}$/u.test(input.id) ||
    !/^[A-Za-z0-9_.:-]{1,160}$/u.test(input.auditReference) ||
    !Number.isFinite(Date.parse(input.createdAt)) ||
    input.summary.trim().length === 0 ||
    input.summary.length > 500 ||
    input.technicalDetails.length > 4_000 ||
    input.impact.length > 2_000 ||
    (input.policyHash !== null && !/^[a-f0-9]{64}$/u.test(input.policyHash)) ||
    (input.policyVersion !== null && input.policyVersion < 1)
  )
    throw new SecurityError("APPROVAL_INPUT_INVALID");
}

function validateHydratedRecord(record: ApprovalRecord): void {
  validateInput(record);
  if (record.userAction !== null)
    assertNoSensitiveMaterial(
      [record.userAction],
      "APPROVAL_SENSITIVE_MATERIAL",
    );
  const open = record.status === "open";
  const decided = record.status === "accepted" || record.status === "rejected";
  if (
    record.payloadHash !== approvalHash(record) ||
    !/^[a-f0-9]{64}$/u.test(record.payloadHash) ||
    (open &&
      (record.revision !== 0 ||
        record.decidedAt !== null ||
        record.decidedBy !== null ||
        record.userAction !== null)) ||
    (decided &&
      (record.revision !== 1 ||
        record.decidedAt === null ||
        record.decidedBy === null ||
        record.userAction === null ||
        !Number.isFinite(Date.parse(record.decidedAt)) ||
        Date.parse(record.decidedAt) < Date.parse(record.createdAt) ||
        !/^[A-Za-z0-9._@-]{1,128}$/u.test(record.decidedBy) ||
        record.userAction.trim().length === 0 ||
        record.userAction.length > 500)) ||
    (!open && !decided)
  )
    throw new SecurityError("APPROVAL_INTEGRITY_INVALID");
}

function freeze<T extends ApprovalRecord>(value: T): T {
  return Object.freeze(value);
}
