import {
  ControlPlaneDatabase,
  type ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import { HackerOneMetadataActionGate } from "../../packages/external-actions/index.js";
import type { HackerOneMetadataReadRuntimeState } from "../../packages/hackerone-readonly/runtime.js";
import { HackerOneMetadataStore } from "../../packages/hackerone-readonly/store.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  decideTestApproval,
  TEST_OPERATOR_ID,
} from "./operator-auth.factory.js";

export interface ActivatedHackerOneActionHarness {
  readonly database: ControlPlaneDatabase;
  readonly controlPlane: ControlPlaneStore;
  readonly metadata: HackerOneMetadataStore;
  readonly actionGate: HackerOneMetadataActionGate;
  close(): void;
}

export function createActivatedHackerOneActionHarness(
  runtime: HackerOneMetadataReadRuntimeState,
  credentialBindingDigest: string,
  at = "2026-07-14T12:00:00.000Z",
): ActivatedHackerOneActionHarness {
  const database = ControlPlaneDatabase.memory();
  const controlPlane = createTestControlPlaneStore(database, at);
  const metadata = new HackerOneMetadataStore(database);
  const actionGate = new HackerOneMetadataActionGate(
    database,
    controlPlane,
    runtime,
  );
  clearTestKillSwitch(controlPlane, at);
  if (runtime.enabled) {
    const approval = actionGate.prepareActivationApproval({
      approvalId: "h1activation-test",
      operatorId: TEST_OPERATOR_ID,
      credentialFingerprint: credentialBindingDigest,
      createdAt: at,
    });
    decideTestApproval(controlPlane, {
      approvalId: approval.id,
      decision: "accepted",
      userAction: "explicit_test_hackerone_metadata_activation",
      issuedAt: at,
    });
  }
  return Object.freeze({
    database,
    controlPlane,
    metadata,
    actionGate,
    close: () => {
      database.close();
    },
  });
}
