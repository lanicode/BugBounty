import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { parseDocument } from "yaml";
import { diffPolicies } from "../control-plane/policy.js";
import { parseProgramImport } from "../control-plane/program-import.js";
import type {
  ControlPlaneStore,
  StoredPolicyVersion,
} from "../control-plane/store.js";
import type { ApprovalRecord, CampaignRecord } from "../control-plane/types.js";
import type { DemoSaas, DemoSaasSnapshot } from "../demo-saas/domain.js";
import {
  LocalProductWorkflow,
  type LocalProductDemoBinding,
  type LocalProductRuntimeContext,
} from "../local-product/index.js";
import type { RuntimeReadiness } from "../local-runtime/index.js";
import type {
  HumanSimulationEvidence,
  SimulationOrchestrator,
  SimulationSummary,
} from "../simulation/orchestrator.js";
import {
  isTrustedOperatorSigner,
  type OperatorSigner,
} from "../operator-auth/index.js";
import { SIMULATION_CONFIRMATION_ORDER } from "../simulation/orchestrator.js";
import { errorCode, SecurityError } from "../shared/errors.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import {
  detectHackerOnePolicyDrift,
  type HackerOneIntegrationStatus,
  type HackerOneMetadataService,
  type HackerOnePolicySnapshot,
  type HackerOneProgram,
  type HackerOneProgramSuitability,
  type StoredHackerOnePolicySnapshot,
  type StoredHackerOneProgram,
} from "../hackerone-readonly/index.js";
import {
  DASHBOARD_CSS,
  DASHBOARD_HTML,
  DASHBOARD_JAVASCRIPT,
} from "./assets.js";
import { DASHBOARD_PHASE8_JAVASCRIPT } from "./phase8-assets.js";
import { HACKERONE_DASHBOARD_JAVASCRIPT } from "./hackerone-assets.js";
import { ACTIVE_TESTING_DASHBOARD_JAVASCRIPT } from "./active-testing-assets.js";
import {
  isTrustedLocalActiveTestingController,
  unavailableActiveTestingProjection,
  type LocalActiveTestingController,
} from "./active-testing.js";
import {
  isTrustedCoreProvisioningController,
  unavailableCoreProvisioningProjection,
  type LocalCoreProvisioningController,
} from "./core-provisioning.js";

const LOOPBACK_HOST = "127.0.0.1";
const MAX_BODY_BYTES = 65_536;
const HACKERONE_CREDENTIAL_FRAME_MAGIC = Object.freeze([
  0x48, 0x31, 0x43, 0x52,
] as const);
const HACKERONE_CREDENTIAL_FRAME_VERSION = 1;
const HACKERONE_CREDENTIAL_FRAME_HEADER_BYTES = 9;
const MAX_HACKERONE_CREDENTIAL_BYTES = 3_000;
const MAX_HACKERONE_CREDENTIAL_FRAME_BYTES =
  HACKERONE_CREDENTIAL_FRAME_HEADER_BYTES + MAX_HACKERONE_CREDENTIAL_BYTES * 2;
const MAX_HACKERONE_MANUAL_IMPORT_SOURCE_BYTES = 1_048_576;
const MAX_HACKERONE_MANUAL_IMPORT_BODY_BYTES =
  MAX_HACKERONE_MANUAL_IMPORT_SOURCE_BYTES * 2 + 1_024;
const MAX_HACKERONE_DASHBOARD_PROGRAMS = 1_000;
const MAX_HACKERONE_DASHBOARD_POLICY_VERSIONS = 20;
const MAX_HACKERONE_DASHBOARD_CAMPAIGNS = 100;
const ACTOR = /^[A-Za-z0-9._@-]{1,128}$/u;
const SECURITY_HEADERS = Object.freeze({
  "cache-control": "no-store",
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; worker-src 'none'",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy":
    "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
});

const CONFIRMATION_KEYS = SIMULATION_CONFIRMATION_ORDER;

interface DashboardApprovalDecisionInput {
  readonly id: string;
  readonly expectedRevision: 0;
  readonly expectedPayloadHash: string;
  readonly decision: "accepted" | "rejected";
  readonly actor: string;
  readonly userAction: string;
}

export interface DashboardDependencies {
  readonly store: ControlPlaneStore;
  readonly demo: DemoSaas;
  readonly localProduct?: LocalProductWorkflow;
  readonly simulation?: SimulationOrchestrator;
  readonly operatorSigner?: OperatorSigner;
  readonly coreProvisioning?: LocalCoreProvisioningController;
  readonly activeTesting?: LocalActiveTestingController;
  readonly readiness: RuntimeReadiness;
  readonly hackerOne?: HackerOneMetadataService;
  readonly now?: () => Date;
}

export interface RunningDashboardServer {
  readonly host: "127.0.0.1";
  readonly port: number;
  readonly origin: string;
  close(): Promise<void>;
}

export async function startDashboardServer(
  dependencies: DashboardDependencies,
  port = 0,
): Promise<RunningDashboardServer> {
  if (!Number.isInteger(port) || port < 0 || port > 65_535)
    throw new Error("DASHBOARD_PORT_INVALID");
  const now = dependencies.now ?? (() => new Date());
  const localProduct =
    dependencies.localProduct ??
    new LocalProductWorkflow(
      now,
      localProductRuntimeContext(dependencies),
      localProductDemoBinding(dependencies.demo.snapshot()),
    );
  const csrfToken = randomBytes(32).toString("base64url");
  const operatorSessionId = randomBytes(32).toString("base64url");
  if (
    dependencies.operatorSigner !== undefined &&
    !isTrustedOperatorSigner(dependencies.operatorSigner)
  )
    throw new SecurityError("OPERATOR_SIGNER_UNTRUSTED");
  if (
    dependencies.coreProvisioning !== undefined &&
    !isTrustedCoreProvisioningController(dependencies.coreProvisioning)
  )
    throw new SecurityError("CORE_PROVISIONING_CONTROLLER_UNTRUSTED");
  if (
    dependencies.activeTesting !== undefined &&
    !isTrustedLocalActiveTestingController(dependencies.activeTesting)
  )
    throw new SecurityError("ACTIVE_TESTING_CONTROLLER_UNTRUSTED");
  const binding: { expectedHost?: string; origin?: string } = {};
  let lastSimulation: SimulationSummary | undefined;
  let simulationRunning = false;

  const server = createServer(
    {
      headersTimeout: 5_000,
      keepAliveTimeout: 1_000,
      maxHeaderSize: 16_384,
      requestTimeout: 10_000,
    },
    (request, response) => {
      void handleRequest(request, response).catch((error: unknown) => {
        if (response.headersSent) {
          response.destroy();
          return;
        }
        sendError(response, error);
      });
    },
  );

  async function handleRequest(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    applySecurityHeaders(response);
    const expectedHost = binding.expectedHost;
    const origin = binding.origin;
    if (request.socket.remoteAddress !== LOOPBACK_HOST)
      throw new DashboardHttpError(403, "DASHBOARD_REMOTE_ADDRESS_BLOCKED");
    if (expectedHost === undefined || request.headers.host !== expectedHost)
      throw new DashboardHttpError(403, "DASHBOARD_HOST_BLOCKED");
    if (origin === undefined)
      throw new DashboardHttpError(503, "DASHBOARD_BINDING_UNAVAILABLE");
    const pathname = parseCanonicalPath(request.url, expectedHost);

    if (request.method === "GET") {
      await serveGet(response, pathname, () =>
        buildDashboardState(
          dependencies,
          csrfToken,
          timestamp(now),
          simulationRunning,
          lastSimulation,
          localProduct,
        ),
      );
      return;
    }
    if (request.method !== "POST") {
      response.setHeader("allow", "GET, POST");
      throw new DashboardHttpError(405, "DASHBOARD_METHOD_BLOCKED");
    }
    if (!isPostRoute(pathname))
      throw new DashboardHttpError(404, "DASHBOARD_ROUTE_NOT_FOUND");
    if (pathname === "/api/hackerone/credentials/store") {
      const declaredLength = assertCredentialMutationHeaders(
        request,
        origin,
        csrfToken,
      );
      const payload = await readBoundedCredentialBody(request, declaredLength);
      let credentials:
        | {
            readonly identifier: Uint8Array;
            readonly token: Uint8Array;
          }
        | undefined;
      try {
        credentials = parseHackerOneCredentialFrame(payload);
        await requireHackerOne(dependencies).storeCredentialBytes(
          credentials.identifier,
          credentials.token,
        );
        sendJson(response, 200, { stored: true, adapterEnabled: false });
      } finally {
        credentials?.identifier.fill(0);
        credentials?.token.fill(0);
        payload.fill(0);
      }
      return;
    }
    const maximumBodyBytes =
      pathname === "/api/hackerone/manual-import"
        ? MAX_HACKERONE_MANUAL_IMPORT_BODY_BYTES
        : MAX_BODY_BYTES;
    assertMutationHeaders(request, origin, csrfToken, maximumBodyBytes);
    const body = await readJsonBody(request, maximumBodyBytes);

    switch (pathname) {
      case "/api/core/provision": {
        const coreProvisioning = requireCoreProvisioning(dependencies);
        sendJson(response, 200, {
          coreProvisioning: await coreProvisioning.provision(body),
        });
        return;
      }
      case "/api/active-testing/plan/prepare": {
        assertSecureCoreReady(dependencies);
        const controller = requireActiveTesting(dependencies);
        const input = parseActiveTestingPlanPreparation(body);
        const at = timestamp(now);
        const signer = requireOperatorSigner(dependencies);
        ensureOperatorEnrolled(
          dependencies.store,
          signer,
          operatorSessionId,
          at,
        );
        const prepared = controller.preparePlanApproval({
          planId: `active-plan-${randomBytes(16).toString("hex")}`,
          approvalId: `active-approval-${randomBytes(16).toString("hex")}`,
          operatorId: signer.credential.operator_id,
          programRef: input.programRef,
          snapshotDigest: input.snapshotDigest,
          scopeId: input.scopeId,
          assetIdentifierDigest: input.assetIdentifierDigest,
          testClass: input.testClass,
          createdAt: at,
          confirmations: input.confirmations,
        });
        sendJson(response, 201, {
          planId: prepared.plan.plan_id,
          planDigest: sha256(canonicalJson(prepared.plan)),
          approvalId: prepared.approval.id,
          requestPerformed: false,
        });
        return;
      }
      case "/api/active-testing/plan/approve": {
        assertSecureCoreReady(dependencies);
        if (dependencies.store.isKillSwitchActive())
          throw new SecurityError("ACTIVE_TEST_KILL_SWITCH");
        const controller = requireActiveTesting(dependencies);
        controller.assertRuntimeEnabled();
        const input = parseActiveTestingPlanAction(body);
        controller.assertApprovalState(input.planId, input.approvalId, "open");
        const at = timestamp(now);
        const signer = requireOperatorSigner(dependencies);
        ensureOperatorEnrolled(
          dependencies.store,
          signer,
          operatorSessionId,
          at,
        );
        const decided = decideDashboardApproval(
          dependencies.store,
          signer,
          operatorSessionId,
          input.approvalId,
          "accepted",
          `explicit_active_test_plan_approval:${input.planId}`,
          at,
        );
        controller.assertApprovalState(
          input.planId,
          input.approvalId,
          "accepted",
        );
        sendJson(response, 200, {
          planId: input.planId,
          approvalId: decided.id,
          approved: true,
          requestPerformed: false,
        });
        return;
      }
      case "/api/active-testing/execution/start": {
        assertSecureCoreReady(dependencies);
        const controller = requireActiveTesting(dependencies);
        controller.assertRuntimeEnabled();
        const input = parseActiveTestingPlanAction(body);
        controller.assertApprovalState(
          input.planId,
          input.approvalId,
          "accepted",
        );
        const completed = await controller.executeConfirmed({
          proposalId: `active-proposal-${randomBytes(16).toString("hex")}`,
          approvalId: input.approvalId,
          planId: input.planId,
          confirmed: true,
        });
        sendJson(response, 200, {
          completed: true,
          planId: input.planId,
          observationDigest: completed.report.observationDigest,
          reportId: completed.report.reportId,
          reviewStatus: "local_draft_unsubmitted",
          externalSubmissionPerformed: false,
        });
        return;
      }
      case "/api/local-product/action": {
        try {
          assertLocalProductRuntimePreconditions(
            body,
            dependencies,
            localProduct,
          );
          sendJson(response, 200, {
            localProduct: localProduct.perform(body),
          });
        } catch (error) {
          if (
            error instanceof Error &&
            /^LOCAL_PRODUCT_[A-Z0-9_]+$/u.test(error.message)
          )
            throw new DashboardHttpError(409, error.message);
          throw error;
        }
        return;
      }
      case "/api/hackerone/credentials/remove": {
        assertEmptyObject(body, "HACKERONE_DASHBOARD_REQUEST_INVALID");
        await requireHackerOne(dependencies).removeCredentials();
        sendJson(response, 200, { removed: true, adapterEnabled: false });
        return;
      }
      case "/api/hackerone/integration/enable": {
        assertSecureCoreReady(dependencies);
        assertEmptyObject(body, "HACKERONE_DASHBOARD_REQUEST_INVALID");
        const service = requireHackerOne(dependencies);
        const serviceStatus = await service.status();
        if (!serviceStatus.adapterConfigured)
          throw new SecurityError("HACKERONE_METADATA_CAPABILITY_DISABLED");
        if (serviceStatus.killSwitchActive)
          throw new SecurityError("HACKERONE_KILL_SWITCH");
        const at = timestamp(now);
        const signer = requireOperatorSigner(dependencies);
        ensureOperatorEnrolled(
          dependencies.store,
          signer,
          operatorSessionId,
          at,
        );
        const approval = await service.prepareActivationApproval({
          approvalId: `h1activation-${randomBytes(16).toString("hex")}`,
          operatorId: signer.credential.operator_id,
          createdAt: at,
        });
        const decided = decideDashboardApproval(
          dependencies.store,
          signer,
          operatorSessionId,
          approval.id,
          "accepted",
          "explicit_local_hackerone_metadata_activation",
          at,
        );
        service.completeActivation();
        sendJson(response, 200, {
          enabled: decided.status === "accepted",
          approvalId: decided.id,
        });
        return;
      }
      case "/api/hackerone/integration/disable": {
        assertEmptyObject(body, "HACKERONE_DASHBOARD_REQUEST_INVALID");
        await requireHackerOne(dependencies).disable();
        sendJson(response, 200, { enabled: false });
        return;
      }
      case "/api/hackerone/connection-test": {
        assertSecureCoreReady(dependencies);
        assertEmptyObject(body, "HACKERONE_DASHBOARD_REQUEST_INVALID");
        const result = await requireHackerOne(dependencies).testConnection();
        if (result.result !== "connected" || !result.schemaValid) {
          sendJson(response, 502, { error: result.redactedStatus });
          return;
        }
        sendJson(response, 200, result);
        return;
      }
      case "/api/hackerone/programs/synchronize": {
        assertSecureCoreReady(dependencies);
        assertEmptyObject(body, "HACKERONE_DASHBOARD_REQUEST_INVALID");
        const result =
          await requireHackerOne(dependencies).synchronizePrograms();
        sendJson(response, 200, result);
        return;
      }
      case "/api/hackerone/program/select": {
        assertSecureCoreReady(dependencies);
        const input = parseHackerOneProgramReference(body);
        await requireHackerOne(dependencies).selectProgram(input.programRef);
        sendJson(response, 200, { selected: true });
        return;
      }
      case "/api/hackerone/program/synchronize": {
        assertSecureCoreReady(dependencies);
        const input = parseHackerOneProgramReference(body);
        const result = await requireHackerOne(
          dependencies,
        ).synchronizeSelectedProgram(input.programRef);
        sendJson(response, 200, result);
        return;
      }
      case "/api/hackerone/campaign/bind": {
        assertSecureCoreReady(dependencies);
        const input = parseHackerOneCampaignBinding(body);
        const service = requireHackerOne(dependencies);
        if (service.selectedProgramRef() !== input.programRef)
          throw new SecurityError(
            "HACKERONE_DASHBOARD_SELECTED_PROGRAM_CONFLICT",
          );
        await service.bindDependentCampaign(input.programRef, input.campaignId);
        sendJson(response, 200, {
          bound: true,
          programRef: input.programRef,
          campaignId: input.campaignId,
        });
        return;
      }
      case "/api/hackerone/policy/accept": {
        assertSecureCoreReady(dependencies);
        if (dependencies.store.isKillSwitchActive())
          throw new SecurityError("HACKERONE_POLICY_ACCEPTANCE_KILL_SWITCH");
        const input = parseHackerOnePolicyAcceptance(body);
        const at = timestamp(now);
        const signer = requireOperatorSigner(dependencies);
        ensureOperatorEnrolled(
          dependencies.store,
          signer,
          operatorSessionId,
          at,
        );
        const service = requireHackerOne(dependencies);
        const approval = await service.preparePolicyAcceptanceApproval({
          approvalId: `h1policy-${randomBytes(16).toString("hex")}`,
          operatorId: signer.credential.operator_id,
          programLocalRef: input.programRef,
          snapshotDigest: input.snapshotDigest,
          createdAt: at,
        });
        decideDashboardApproval(
          dependencies.store,
          signer,
          operatorSessionId,
          approval.id,
          "accepted",
          "explicit_local_hackerone_snapshot_acceptance",
          at,
        );
        const result = service.currentSnapshot(input.programRef);
        if (result?.snapshot.snapshotDigest !== input.snapshotDigest)
          throw new SecurityError("HACKERONE_POLICY_ACCEPTANCE_CONFLICT");
        sendJson(response, 200, {
          accepted: !result.acceptancePending,
          snapshotDigest: result.snapshot.snapshotDigest,
        });
        return;
      }
      case "/api/hackerone/manual-import": {
        assertSecureCoreReady(dependencies);
        const input = parseHackerOneManualImport(body);
        const result = await requireHackerOne(dependencies).importManual(
          input.source,
        );
        sendJson(response, 201, {
          programRef: result.programLocalRef,
          snapshotDigest: result.snapshot.snapshotDigest,
          source: result.snapshot.source,
        });
        return;
      }
      case "/api/programs/import": {
        assertSecureCoreReady(dependencies);
        const imported = parseImportRequest(body);
        const program = dependencies.store.createProgram(
          parseProgramImport(imported.source, imported.format),
          timestamp(now),
        );
        sendJson(response, 201, { program });
        return;
      }
      case "/api/simulation/run": {
        assertSecureCoreReady(dependencies);
        if (dependencies.simulation === undefined)
          throw new DashboardHttpError(
            409,
            "DASHBOARD_SECURE_SIMULATION_UNAVAILABLE",
          );
        if (simulationRunning)
          throw new DashboardHttpError(409, "SIMULATION_ALREADY_RUNNING");
        const evidence = parseSimulationRequest(body, timestamp(now));
        simulationRunning = true;
        try {
          lastSimulation = await dependencies.simulation.run(evidence);
          sendJson(response, 200, lastSimulation);
        } finally {
          simulationRunning = false;
        }
        return;
      }
      case "/api/kill-switch/engage":
      case "/api/kill-switch/clear": {
        const input = parseKillSwitchRequest(body);
        const at = timestamp(now);
        const engaging = pathname.endsWith("/engage");
        if (!engaging) assertSecureCoreReady(dependencies);
        let result: { readonly active: boolean; readonly revision: number };
        if (engaging) {
          try {
            result = dependencies.store.setKillSwitch(true, input.actor, at);
          } finally {
            dependencies.hackerOne?.engageKillSwitch();
          }
        } else {
          result = clearKillSwitchWithSigner(
            dependencies,
            operatorSessionId,
            input.actor,
            at,
          );
        }
        sendJson(response, 200, result);
        return;
      }
      case "/api/approvals/decide": {
        assertSecureCoreReady(dependencies);
        const at = timestamp(now);
        const input = parseApprovalDecisionRequest(body);
        const signer = requireOperatorSigner(dependencies);
        assertSignerMatchesActor(signer, input.actor);
        ensureOperatorEnrolled(
          dependencies.store,
          signer,
          operatorSessionId,
          at,
        );
        const context = dependencies.store.describeApprovalDecision(input.id);
        if (
          input.expectedRevision !== context.expectedRevision ||
          input.expectedPayloadHash !== context.approvalPayloadHashSha256
        )
          throw new SecurityError("DASHBOARD_APPROVAL_DECISION_STALE");
        const approval = dependencies.store.decideApproval(
          signer.signApprovalDecision({
            controlPlaneId: context.controlPlaneId,
            approvalId: context.approvalId,
            approvalKind: context.approvalKind,
            approvalPayloadHashSha256: context.approvalPayloadHashSha256,
            expectedRevision: context.expectedRevision,
            decision: input.decision,
            userAction: input.userAction,
            contextDigestSha256: context.contextDigestSha256,
            sessionId: operatorSessionId,
            nonce: randomBytes(32).toString("base64url"),
            issuedAt: at,
            expiresAt: operatorStatementExpiry(at),
          }),
        );
        sendJson(response, 200, { approval });
        return;
      }
    }
  }

  server.on("upgrade", (_request, socket) => {
    socket.destroy();
  });
  server.on("clientError", (_error, socket) => {
    socket.destroy();
  });

  await listen(server, port);
  const address = server.address();
  if (!isLoopbackAddress(address)) {
    await closeServer(server);
    throw new Error("DASHBOARD_BIND_INVALID");
  }
  binding.expectedHost = `${LOOPBACK_HOST}:${address.port}`;
  binding.origin = `http://${binding.expectedHost}`;
  let closePromise: Promise<void> | undefined;

  return Object.freeze({
    host: LOOPBACK_HOST,
    port: address.port,
    origin: binding.origin,
    close: () => {
      closePromise ??= closeServer(server);
      return closePromise;
    },
  });
}

function localProductRuntimeContext(
  dependencies: DashboardDependencies,
): LocalProductRuntimeContext {
  return Object.freeze({
    systemStatus: dependencies.readiness.platformStatus,
    secretStoreStatus: dependencies.readiness.secretStoreStatus,
    demoSaasStatus: dependencies.readiness.demoSaasStatus,
    databaseStatus: dependencies.readiness.databaseStatus,
    demoSnapshotDigest: sha256(canonicalJson(dependencies.demo.snapshot())),
  });
}

function localProductDemoBinding(
  snapshot: DemoSaasSnapshot,
): LocalProductDemoBinding {
  const identities = snapshot.organization.identities;
  const project = snapshot.projects[0];
  const document = snapshot.documents[0];
  const invitation = snapshot.invitations[0];
  const testObject = snapshot.testObjects[0];
  if (
    snapshot.revision !== 1 ||
    snapshot.organization.organizationRef !== "org-demo-001" ||
    identities.length !== 3 ||
    identities[0]?.role !== "Owner" ||
    identities[0].identityRef !== "identity-owner-001" ||
    identities[1]?.role !== "Member" ||
    identities[1].identityRef !== "identity-member-001" ||
    identities[2]?.role !== "External" ||
    identities[2].identityRef !== "identity-external-001" ||
    snapshot.projects.length !== 1 ||
    project?.projectRef !== "project-demo-001" ||
    project.organizationRef !== "org-demo-001" ||
    project.createdByRef !== "identity-owner-001" ||
    snapshot.documents.length !== 1 ||
    document?.documentRef !== "document-demo-001" ||
    document.projectRef !== "project-demo-001" ||
    document.createdByRef !== "identity-member-001" ||
    snapshot.invitations.length !== 1 ||
    invitation?.invitationRef !== "invitation-demo-001" ||
    invitation.organizationRef !== "org-demo-001" ||
    invitation.createdByRef !== "identity-owner-001" ||
    snapshot.testObjects.length !== 1 ||
    testObject?.objectRef !== "object-demo-001" ||
    testObject.projectRef !== "project-demo-001" ||
    testObject.controlledByRef !== "identity-owner-001" ||
    snapshot.currentPolicy.version !== 1 ||
    snapshot.policyVersions.length !== 1 ||
    snapshot.policyVersions[0]?.contentHash !==
      snapshot.currentPolicy.contentHash ||
    snapshot.lastPolicyDrift !== null ||
    !/^[a-f0-9]{64}$/u.test(snapshot.currentPolicy.contentHash)
  )
    throw new SecurityError("DASHBOARD_LOCAL_DEMO_FIXTURE_INVALID");

  return Object.freeze({
    snapshotDigest: sha256(canonicalJson(snapshot)),
    organizationRef: "org-demo-001",
    identities: Object.freeze([
      Object.freeze({
        role: "Owner" as const,
        identityRef: "identity-owner-001" as const,
      }),
      Object.freeze({
        role: "Member" as const,
        identityRef: "identity-member-001" as const,
      }),
      Object.freeze({
        role: "External" as const,
        identityRef: "identity-external-001" as const,
      }),
    ] as const),
    controlledObjectRef: "object-demo-001",
    controlledByRef: "identity-owner-001",
    canaryDigest: sha256(testObject.canary),
    demoPolicyHash: snapshot.currentPolicy.contentHash,
  });
}

function assertLocalProductRuntimePreconditions(
  value: unknown,
  dependencies: DashboardDependencies,
  localProduct: LocalProductWorkflow,
): void {
  const readiness = dependencies.readiness;
  const expectedDemoDigest =
    localProduct.snapshot().runtimeContext.demoSnapshotDigest;
  if (
    sha256(canonicalJson(dependencies.demo.snapshot())) !== expectedDemoDigest
  )
    throw new DashboardHttpError(409, "DASHBOARD_LOCAL_DEMO_DRIFT_BLOCKED");
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return;
  const descriptor = Object.getOwnPropertyDescriptor(value, "action");
  if (descriptor === undefined || !("value" in descriptor)) return;
  const action: unknown = descriptor.value;
  if (
    action === "onboarding_system_check" &&
    (readiness.databaseStatus !== "ready" ||
      readiness.demoSaasStatus !== "ready")
  )
    throw new DashboardHttpError(409, "DASHBOARD_LOCAL_SYSTEM_CHECK_BLOCKED");
  if (
    action === "onboarding_secret_store_check" &&
    readiness.secretStoreStatus === "blocked"
  )
    throw new DashboardHttpError(
      409,
      "DASHBOARD_LOCAL_SECRET_STORE_CHECK_BLOCKED",
    );
  if (
    action === "onboarding_initialize_demo" &&
    readiness.demoSaasStatus !== "ready"
  )
    throw new DashboardHttpError(409, "DASHBOARD_LOCAL_DEMO_CHECK_BLOCKED");
}

function assertSecureCoreReady(dependencies: DashboardDependencies): void {
  if (!dependencies.readiness.ready)
    throw new DashboardHttpError(409, "DASHBOARD_SECURE_CORE_NOT_READY");
}

async function serveGet(
  response: ServerResponse,
  pathname: string,
  state: () => Promise<unknown>,
): Promise<void> {
  switch (pathname) {
    case "/":
      sendText(response, 200, "text/html; charset=utf-8", DASHBOARD_HTML);
      return;
    case "/app.js":
      sendText(
        response,
        200,
        "text/javascript; charset=utf-8",
        DASHBOARD_JAVASCRIPT,
      );
      return;
    case "/phase8.js":
      sendText(
        response,
        200,
        "text/javascript; charset=utf-8",
        DASHBOARD_PHASE8_JAVASCRIPT,
      );
      return;
    case "/hackerone.js":
      sendText(
        response,
        200,
        "text/javascript; charset=utf-8",
        HACKERONE_DASHBOARD_JAVASCRIPT,
      );
      return;
    case "/active-testing.js":
      sendText(
        response,
        200,
        "text/javascript; charset=utf-8",
        ACTIVE_TESTING_DASHBOARD_JAVASCRIPT,
      );
      return;
    case "/styles.css":
      sendText(response, 200, "text/css; charset=utf-8", DASHBOARD_CSS);
      return;
    case "/api/state":
      sendJson(response, 200, await state());
      return;
    case "/health":
      sendJson(response, 200, {
        status: "ok",
        mode: "simulation",
        externalIntegrationsEnabled: false,
      });
      return;
    default:
      throw new DashboardHttpError(404, "DASHBOARD_ROUTE_NOT_FOUND");
  }
}

async function buildDashboardState(
  dependencies: DashboardDependencies,
  csrfToken: string,
  generatedAt: string,
  simulationRunning: boolean,
  lastSimulation: SimulationSummary | undefined,
  localProduct: LocalProductWorkflow,
): Promise<unknown> {
  const programs = dependencies.store.listPrograms();
  const storedPolicies = programs.flatMap((program) =>
    dependencies.store.listPolicies(program.id),
  );
  const campaigns = dependencies.store.listCampaigns();
  const approvals = dependencies.store.listApprovals();
  const identities = dependencies.store.listIdentities();
  const ownedObjects = dependencies.store.listOwnedObjects();
  const reports = dependencies.store.listReportDrafts();
  const auditEntries = dependencies.store.listAuditEntries();
  const killSwitchActive = dependencies.store.isKillSwitchActive();
  const demo = dependencies.demo.snapshot();
  const localProductSnapshot = localProduct.snapshot();
  const currentDemoDigest = sha256(canonicalJson(demo));
  const expectedDemoDigest =
    localProductSnapshot.runtimeContext.demoSnapshotDigest;
  const demoBindingValid = currentDemoDigest === expectedDemoDigest;
  const simulationReview =
    dependencies.simulation?.preview() ?? unavailableSimulationReview();
  const policyDiffs = makePolicyDiffs(
    programs.map(({ id }) => id),
    dependencies.store,
  );
  const completed = lastSimulation !== undefined || reports.length > 0;
  const hackerOne = await buildHackerOneDashboardState(
    dependencies.hackerOne,
    campaigns,
    dependencies.readiness,
  );
  const coreProvisioning =
    dependencies.coreProvisioning === undefined
      ? unavailableCoreProvisioningProjection()
      : await dependencies.coreProvisioning.project();
  const activeTesting = isTrustedLocalActiveTestingController(
    dependencies.activeTesting,
  )
    ? dependencies.activeTesting.project({
        secureCoreReady: dependencies.readiness.ready,
        operatorSignerAvailable: isTrustedOperatorSigner(
          dependencies.operatorSigner,
        ),
        killSwitchActive,
        now: generatedAt,
      })
    : unavailableActiveTestingProjection(
        dependencies.readiness.ready,
        killSwitchActive,
      );

  return {
    version: 1,
    mode: "simulation",
    runtimeMode: dependencies.readiness.ready
      ? "local_simulation"
      : "local_setup_shell",
    externalIntegrationsEnabled: false,
    aiProviderStatus: "disabled_not_implemented",
    runtimeReadiness: dependencies.readiness,
    coreProvisioning,
    activeTesting,
    localProduct: localProductSnapshot,
    localProductIntegrity: {
      status: demoBindingValid ? "bound" : "blocked_demo_drift",
      expectedDemoDigest,
      currentDemoDigest,
      evidenceStatus:
        localProductSnapshot.evidence === null
          ? "not_created"
          : demoBindingValid
            ? "valid_bound"
            : "stale_blocked",
      reportStatus:
        localProductSnapshot.report === null
          ? "not_created"
          : demoBindingValid
            ? "valid_bound"
            : "stale_blocked",
    },
    hackerOne,
    phase1SecurityStatus: "enforced",
    simulationStatus: simulationRunning
      ? "running"
      : completed
        ? "completed"
        : dependencies.simulation === undefined || !dependencies.readiness.ready
          ? "setup_required"
          : "ready",
    simulationAvailable:
      dependencies.simulation !== undefined && dependencies.readiness.ready,
    eventStoreStatus:
      dependencies.simulation !== undefined && dependencies.readiness.ready
        ? "secure_open_on_demand"
        : "not_started_setup_required",
    localStorageLocations: {
      controlPlane: ".local/dashboard/control-plane.sqlite",
      eventStore:
        dependencies.simulation !== undefined && dependencies.readiness.ready
          ? ".local/dashboard/event-store (secure open on demand)"
          : "not initialized (secure setup required)",
      browserHarness: ".local/phase7-playwright (tests only)",
    },
    generatedAt,
    csrfToken,
    operatorAuthentication: {
      signerConfigured: isTrustedOperatorSigner(dependencies.operatorSigner),
      operatorId: isTrustedOperatorSigner(dependencies.operatorSigner)
        ? dependencies.operatorSigner.credential.operator_id
        : null,
    },
    simulationReview,
    killSwitch: { active: killSwitchActive },
    counts: {
      programs: programs.length,
      activeCampaigns: campaigns.filter(
        ({ state }) => state === "running_simulation",
      ).length,
      pausedCampaigns: campaigns.filter(({ state }) => state === "paused")
        .length,
      openApprovals: approvals.filter(({ status }) => status === "open").length,
      privacyAlerts: approvals.filter(
        ({ kind, status }) => kind === "privacy_alert" && status === "open",
      ).length,
      reportDrafts: reports.length,
      identities: identities.length,
      ownedObjects: ownedObjects.length,
      policyVersions: storedPolicies.length,
    },
    programs,
    policies: storedPolicies.map((stored) => ({
      programId: stored.programId,
      version: stored.version,
      policyHash: stored.policy.policyHash,
      acceptedBy: stored.acceptance?.acceptedBy ?? null,
      requestLimits: stored.policy.requestLimits,
      forbiddenTestClasses: stored.policy.forbiddenTestClasses,
      unclearRules: stored.policy.unclearRules,
    })),
    policyDiffs,
    campaigns: campaigns.map((campaign) => ({
      id: campaign.id,
      programId: campaign.programId,
      policyVersion: campaign.policyVersion,
      policyHash: campaign.policyHash,
      state: campaign.state,
      revision: campaign.revision,
      humanApprovedBy: campaign.humanApprovedBy,
      maxRequests: campaign.contract.maxRequests,
      requestsPerMinute: campaign.contract.requestsPerMinute,
      maxConcurrency: campaign.contract.maxConcurrency,
      killSwitchStatus: campaign.killSwitchStatus,
    })),
    approvals: approvals.map((approval) => ({
      id: approval.id,
      kind: approval.kind,
      summary: approval.summary,
      technicalDetails: approval.technicalDetails,
      impact: approval.impact,
      policyVersion: approval.policyVersion,
      policyHash: approval.policyHash,
      status: approval.status,
      decidedAt: approval.decidedAt,
      decidedBy: approval.decidedBy,
      userAction: approval.userAction,
      auditReference: approval.auditReference,
      payloadHash: approval.payloadHash,
      revision: approval.revision,
    })),
    identities: identities.map((identity) => ({
      id: identity.id,
      programId: identity.programId,
      role: identity.role,
      status: identity.status,
      humanActionRequired: identity.humanActionRequired,
      organizationRef: identity.organizationRef,
    })),
    ownedObjects: ownedObjects.map((object) => ({
      objectRef: object.objectRef,
      programId: object.programId,
      campaignId: object.campaignId,
      accountId: object.accountId,
      tenantRef: object.tenantRef,
      objectType: object.objectType,
      status: object.status,
      allowedActions: object.allowedActions,
      expiresAt: object.expiresAt,
    })),
    reports: reports.map((report) => ({
      id: report.id,
      campaignId: report.campaignId,
      title: report.title,
      summary: report.summary,
      status: report.status,
      externalSubmissionPerformed: false,
    })),
    expert: {
      policyDecisions:
        programs.length === 0
          ? ["Keine Policy-Entscheidungen vorhanden."]
          : programs.map(
              (program) =>
                `${program.id}: ${program.ruleAcceptanceStatus}; Hash ${program.currentPolicyHash ?? "nicht gesetzt"}`,
            ),
      auditLog:
        auditEntries.length === 0
          ? ["Bodyfreies Control-Plane-Audit aktiv; noch keine Einträge."]
          : auditEntries.map(
              (entry) =>
                `${entry.occurredAt}: ${entry.action} / ${entry.decision} / ${entry.reasonCode}`,
            ),
      requestBudgets:
        campaigns.length === 0
          ? ["Keine Kampagnenbudgets vorhanden."]
          : campaigns.map(
              (campaign) =>
                `${campaign.id}: ${String(campaign.contract.maxRequests)} gesamt, ${String(campaign.contract.requestsPerMinute)}/min, Parallelität ${String(campaign.contract.maxConcurrency)}`,
            ),
      ownershipLedger: [
        `${String(ownedObjects.length)} kontrollierte Objektreferenzen`,
        "Unbekannte Objekt-IDs werden blockiert.",
        "Canaries erscheinen im Dashboard ausschließlich als geschützte Ledger-Metadaten.",
      ],
      adapterStatus: [
        "MockPlatformAdapter: lokal verfügbar",
        "Demo-SaaS: " + demo.organization.organizationRef,
        `HackerOne-Metadaten: ${hackerOneStatusText(hackerOne)}`,
        "Bugcrowd und alle schreibenden Plattformadapter: deaktiviert",
      ],
      eventStore: [
        "Eventdaten: ausschließlich AES-256-GCM-verschlüsselt",
        "Roh-HAR und unredigierte Responses: deaktiviert",
      ],
      configurationDiagnosis: [
        "Allgemeine external_integrations_enabled: false",
        "Allgemeine Zielrequest-Klasse: ausschließlich 127.0.0.1",
        "Separate HackerOne-Capability: nur Metadaten-GETs bei expliziter Aktivierung",
        `Globaler Kill Switch: ${killSwitchActive ? "aktiv" : "freigegeben"}`,
        "Fehlerzustände werden fail-closed behandelt.",
      ],
    },
  };
}

function hackerOneStatusText(value: unknown): string {
  if (value === null || typeof value !== "object") return "deaktiviert";
  try {
    const status: unknown = Reflect.get(value, "status");
    if (status === null || typeof status !== "object") return "deaktiviert";
    return Reflect.get(status, "adapterEnabled") === true
      ? "read-only aktiviert"
      : "deaktiviert";
  } catch {
    return "deaktiviert";
  }
}

async function buildHackerOneDashboardState(
  service: HackerOneMetadataService | undefined,
  campaigns: readonly CampaignRecord[],
  readiness: RuntimeReadiness,
): Promise<unknown> {
  const secureCoreReasonCodes = Object.freeze([...readiness.reasonCodes]);
  if (service === undefined)
    return Object.freeze({
      available: false,
      secureCoreReady: readiness.ready,
      secureCoreReasonCodes,
      status: Object.freeze({
        actionClass: "HACKERONE_METADATA_READ",
        status: "deactivated",
        externalIntegrationsEnabled: false,
        adapterConfigured: false,
        adapterEnabled: false,
        killSwitchActive: true,
        identifierPresent: false,
        tokenPresent: false,
        tokenFingerprint: null,
        lastConnectionTestAt: null,
        lastSuccessfulConnectionAt: null,
        lastConnectionResult: null,
        lastSynchronizationAt: null,
        lastSynchronizationResult: null,
        importedProgramCount: 0,
        lastErrorCode: "HACKERONE_SERVICE_UNAVAILABLE",
        selectedHandle: null,
        apiMode: "read_only",
        targetRequestsEnabled: false,
        reportSubmissionEnabled: false,
      }),
      programs: Object.freeze([]),
      programCount: 0,
      programsTruncated: false,
      selectedProgramRef: null,
      currentSnapshot: null,
      policyVersions: Object.freeze([]),
      policyVersionCount: 0,
      policyVersionsTruncated: false,
      previousPolicy: null,
      campaigns: Object.freeze([]),
      campaignCount: campaigns.length,
      campaignsTruncated: campaigns.length > MAX_HACKERONE_DASHBOARD_CAMPAIGNS,
      drift: null,
    });
  const status = await service.status();
  const allPrograms = service.listPrograms();
  const selectedProgramRef = service.selectedProgramRef();
  const current =
    selectedProgramRef === null
      ? undefined
      : service.currentSnapshot(selectedProgramRef);
  const versions =
    selectedProgramRef === null
      ? Object.freeze([])
      : service.policyVersions(selectedProgramRef);
  const previous = versions.at(-2);
  const drift =
    previous === undefined || current === undefined
      ? null
      : detectHackerOnePolicyDrift(
          previous.snapshot,
          current.snapshot,
          selectedProgramRef !== null &&
            service.hasPausedDependentCampaigns(selectedProgramRef),
        );
  const programs = boundedHackerOnePrograms(
    allPrograms,
    selectedProgramRef,
    service,
  );
  const versionOffset = Math.max(
    0,
    versions.length - MAX_HACKERONE_DASHBOARD_POLICY_VERSIONS,
  );
  const projectedVersions = versions
    .slice(versionOffset)
    .map((version, index) =>
      projectHackerOnePolicyVersion(version, versionOffset + index + 1),
    );
  return Object.freeze({
    available: true,
    secureCoreReady: readiness.ready,
    secureCoreReasonCodes,
    status: projectHackerOneStatus(status),
    programs,
    programCount: allPrograms.length,
    programsTruncated: programs.length < allPrograms.length,
    selectedProgramRef,
    currentSnapshot:
      current === undefined ? null : projectCurrentHackerOneSnapshot(current),
    policyVersions: Object.freeze(projectedVersions),
    policyVersionCount: versions.length,
    policyVersionsTruncated: projectedVersions.length < versions.length,
    previousPolicy:
      previous === undefined ? null : projectPreviousHackerOnePolicy(previous),
    campaigns: boundedHackerOneCampaigns(campaigns),
    campaignCount: campaigns.length,
    campaignsTruncated: campaigns.length > MAX_HACKERONE_DASHBOARD_CAMPAIGNS,
    drift,
  });
}

function boundedHackerOneCampaigns(
  campaigns: readonly CampaignRecord[],
): readonly unknown[] {
  return Object.freeze(
    campaigns.slice(0, MAX_HACKERONE_DASHBOARD_CAMPAIGNS).map((campaign) =>
      Object.freeze({
        id: campaign.id,
        programId: campaign.programId,
        policyVersion: campaign.policyVersion,
        policyHash: campaign.policyHash,
        state: campaign.state,
        revision: campaign.revision,
        killSwitchStatus: campaign.killSwitchStatus,
      }),
    ),
  );
}

function boundedHackerOnePrograms(
  programs: readonly StoredHackerOneProgram[],
  selectedProgramRef: string | null,
  service: HackerOneMetadataService,
): readonly unknown[] {
  const bounded = programs.slice(0, MAX_HACKERONE_DASHBOARD_PROGRAMS);
  if (
    selectedProgramRef !== null &&
    !bounded.some(({ localRef }) => localRef === selectedProgramRef)
  ) {
    const selected = programs.find(
      ({ localRef }) => localRef === selectedProgramRef,
    );
    if (selected !== undefined) {
      if (bounded.length === MAX_HACKERONE_DASHBOARD_PROGRAMS) bounded.pop();
      bounded.push(selected);
    }
  }
  return Object.freeze(
    bounded.map((program) =>
      projectHackerOneProgramSummary(
        program,
        service.currentSnapshot(program.localRef)?.snapshot.suitability ?? null,
      ),
    ),
  );
}

function projectHackerOneStatus(
  status: HackerOneIntegrationStatus,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    actionClass: status.actionClass,
    status: status.status,
    externalIntegrationsEnabled: status.externalIntegrationsEnabled,
    adapterConfigured: status.adapterConfigured,
    adapterEnabled: status.adapterEnabled,
    killSwitchActive: status.killSwitchActive,
    identifierPresent: status.identifierPresent,
    tokenPresent: status.tokenPresent,
    tokenFingerprint: status.tokenFingerprint,
    lastConnectionTestAt: status.lastConnectionTestAt,
    lastSuccessfulConnectionAt: status.lastSuccessfulConnectionAt,
    lastConnectionResult: status.lastConnectionResult,
    lastSynchronizationAt: status.lastSynchronizationAt,
    lastSynchronizationResult: status.lastSynchronizationResult,
    importedProgramCount: status.importedProgramCount,
    lastErrorCode: status.lastErrorCode,
    selectedHandle: status.selectedHandle,
    apiMode: status.apiMode,
    targetRequestsEnabled: status.targetRequestsEnabled,
    reportSubmissionEnabled: status.reportSubmissionEnabled,
  });
}

function projectHackerOneProgramSummary(
  record: StoredHackerOneProgram,
  suitability: HackerOneProgramSuitability | null,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    localRef: record.localRef,
    source: record.program.source,
    catalogActive: record.catalogActive,
    catalogDriftPending: record.catalogDriftPending,
    currentSnapshotDigest: record.currentSnapshotDigest,
    suitability:
      suitability === null
        ? null
        : Object.freeze({
            score: suitability.score,
            reasons: Object.freeze([...suitability.reasons]),
            automationPermission: suitability.automationPermission,
            accountWorkflows: suitability.accountWorkflows,
            legalDecisionMade: suitability.legalDecisionMade,
          }),
    program: projectHackerOneProgram(record.program, false),
  });
}

function projectHackerOneProgram(
  program: HackerOneProgram,
  includePolicy: boolean,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    hackerOneId: program.hackerOneId,
    handle: program.handle,
    name: program.name,
    currency: program.currency,
    ...(includePolicy ? { policy: program.policy } : {}),
    submissionState: program.submissionState,
    programState: program.programState,
    offersBounties: program.offersBounties,
    openScope: program.openScope,
    goldStandardSafeHarbor: program.goldStandardSafeHarbor,
    bookmarked: program.bookmarked,
    ownReportCount: program.ownReportCount,
    ownValidReportCount: program.ownValidReportCount,
    startedAcceptingAt: program.startedAcceptingAt,
    createdAt: program.createdAt,
    updatedAt: program.updatedAt,
    synchronizedAt: program.synchronizedAt,
    source: program.source,
  });
}

function projectCurrentHackerOneSnapshot(
  stored: StoredHackerOnePolicySnapshot,
): Readonly<Record<string, unknown>> {
  const snapshot = stored.snapshot;
  return Object.freeze({
    programLocalRef: stored.programLocalRef,
    acceptancePending: stored.acceptancePending,
    snapshot: Object.freeze({
      program: projectHackerOneProgram(snapshot.program, true),
      structuredScopes: Object.freeze(
        snapshot.structuredScopes.map((scope) =>
          Object.freeze({
            id: scope.id,
            assetType: scope.assetType,
            assetIdentifier: scope.assetIdentifier,
            assetIdentifierDigest: scope.assetIdentifierDigest,
            eligibleForSubmission: scope.eligibleForSubmission,
            eligibleForBounty: scope.eligibleForBounty,
            instruction: scope.instruction,
            maximumSeverity: scope.maximumSeverity,
            createdAt: scope.createdAt,
            updatedAt: scope.updatedAt,
            confidentialityRequirement: scope.confidentialityRequirement,
            integrityRequirement: scope.integrityRequirement,
            availabilityRequirement: scope.availabilityRequirement,
          }),
        ),
      ),
      scopeExclusions: Object.freeze(
        snapshot.scopeExclusions.map((exclusion) =>
          Object.freeze({
            id: exclusion.id,
            category: exclusion.category,
            details: exclusion.details,
            createdAt: exclusion.createdAt,
            updatedAt: exclusion.updatedAt,
          }),
        ),
      ),
      fetchedAt: snapshot.fetchedAt,
      adapterVersion: snapshot.adapterVersion,
      schemaVersion: snapshot.schemaVersion,
      snapshotDigest: snapshot.snapshotDigest,
      policyDigest: snapshot.policyDigest,
      previousSnapshotDigest: snapshot.previousSnapshotDigest,
      suitability: Object.freeze({
        score: snapshot.suitability.score,
        reasons: Object.freeze([...snapshot.suitability.reasons]),
        automationPermission: snapshot.suitability.automationPermission,
        accountWorkflows: snapshot.suitability.accountWorkflows,
        legalDecisionMade: snapshot.suitability.legalDecisionMade,
      }),
      source: snapshot.source,
    }),
  });
}

function projectHackerOnePolicyVersion(
  stored: StoredHackerOnePolicySnapshot,
  versionNumber: number,
): Readonly<Record<string, unknown>> {
  const snapshot: HackerOnePolicySnapshot = stored.snapshot;
  return Object.freeze({
    versionNumber,
    programLocalRef: stored.programLocalRef,
    acceptancePending: stored.acceptancePending,
    snapshot: Object.freeze({
      snapshotDigest: snapshot.snapshotDigest,
      policyDigest: snapshot.policyDigest,
      previousSnapshotDigest: snapshot.previousSnapshotDigest,
      fetchedAt: snapshot.fetchedAt,
      adapterVersion: snapshot.adapterVersion,
      schemaVersion: snapshot.schemaVersion,
      source: snapshot.source,
    }),
  });
}

function projectPreviousHackerOnePolicy(
  stored: StoredHackerOnePolicySnapshot,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    snapshotDigest: stored.snapshot.snapshotDigest,
    policyDigest: stored.snapshot.policyDigest,
    fetchedAt: stored.snapshot.fetchedAt,
    source: stored.snapshot.source,
    policy: stored.snapshot.program.policy,
  });
}

function unavailableSimulationReview(): unknown {
  const policy = Object.freeze({
    hash: "unavailable",
    text: "Secure simulation prerequisites are not configured.",
    allowedAssets: Object.freeze([]),
    excludedAssets: Object.freeze([]),
    allowedTestClasses: Object.freeze([]),
    forbiddenTestClasses: Object.freeze(["active_security_test"]),
    rules: Object.freeze(["fail_closed"]),
    unclearRules: Object.freeze([]),
    requestLimits: Object.freeze({
      maxRequestsTotal: 0,
      maxRequestsPerMinute: 0,
      maxConcurrency: 1,
    }),
  });
  const campaign = Object.freeze({
    approvalDigest: "unavailable",
    policyHash: "unavailable",
    approvedAssets: Object.freeze([]),
    approvedRiskTiers: Object.freeze([]),
    accountRefs: Object.freeze([]),
    allowedActionClasses: Object.freeze([]),
    contract: Object.freeze({
      allowedHosts: Object.freeze([]),
      excludedHosts: Object.freeze([]),
      allowedMethods: Object.freeze(["GET", "HEAD"]),
      maxRequests: 0,
      requestsPerMinute: 0,
      maxConcurrency: 1,
      writeActionsAllowed: false,
      rollbackRequired: true,
      humanCheckpoints: Object.freeze(["secure_setup_required"]),
      validFrom: "unavailable",
      validUntil: "unavailable",
    }),
  });
  return Object.freeze({
    version: 1,
    reviewDigest: "",
    policyV1: policy,
    campaignV1: campaign,
    policyV2: policy,
    policyDiff: Object.freeze({
      changedRequestLimits: Object.freeze([]),
      newlyForbiddenTestClasses: Object.freeze([]),
      newlyAllowedTestClasses: Object.freeze([]),
      changedRulesAdded: Object.freeze([]),
      changedRulesRemoved: Object.freeze([]),
      unclearRules: Object.freeze([]),
    }),
    campaignV2: campaign,
    reportAction: "queue_local_review_only_no_submission",
  });
}

function makePolicyDiffs(
  programIds: readonly string[],
  store: ControlPlaneStore,
): readonly unknown[] {
  return programIds.flatMap((programId) => {
    const policies = store.listPolicies(programId);
    const records: unknown[] = [];
    for (let index = 1; index < policies.length; index += 1) {
      const before = requirePolicy(policies[index - 1]);
      const after = requirePolicy(policies[index]);
      const diff = diffPolicies(before.policy, after.policy);
      records.push({
        programId,
        fromVersion: before.version,
        toVersion: after.version,
        addedAssets: diff.addedAssets,
        removedAssets: diff.removedAssets,
        newlyForbiddenTestClasses: diff.newlyForbiddenTestClasses,
        newlyAllowedTestClasses: diff.newlyAllowedTestClasses,
        changedRequestLimits: diff.changedRequestLimits.map(
          ({ field, before: previous, after: next }) =>
            `${field}: ${String(previous)} → ${String(next)}`,
        ),
        changedRules: {
          added: diff.changedRules.added,
          removed: diff.changedRules.removed,
        },
        unclearRules: diff.unclearRules.current,
      });
    }
    return records;
  });
}

function requirePolicy(
  value: StoredPolicyVersion | undefined,
): StoredPolicyVersion {
  if (value === undefined) throw new SecurityError("DASHBOARD_POLICY_MISSING");
  return value;
}

function parseCanonicalPath(rawUrl: string | undefined, host: string): string {
  if (
    rawUrl === undefined ||
    !rawUrl.startsWith("/") ||
    rawUrl.startsWith("//")
  )
    throw new DashboardHttpError(400, "DASHBOARD_URL_INVALID");
  let url: URL;
  try {
    url = new URL(rawUrl, `http://${host}`);
  } catch {
    throw new DashboardHttpError(400, "DASHBOARD_URL_INVALID");
  }
  if (url.search !== "" || url.hash !== "" || url.pathname !== rawUrl)
    throw new DashboardHttpError(404, "DASHBOARD_ROUTE_NOT_FOUND");
  return url.pathname;
}

function isPostRoute(pathname: string): boolean {
  return (
    pathname === "/api/core/provision" ||
    pathname === "/api/active-testing/plan/prepare" ||
    pathname === "/api/active-testing/plan/approve" ||
    pathname === "/api/active-testing/execution/start" ||
    pathname === "/api/local-product/action" ||
    pathname === "/api/hackerone/credentials/store" ||
    pathname === "/api/hackerone/credentials/remove" ||
    pathname === "/api/hackerone/integration/enable" ||
    pathname === "/api/hackerone/integration/disable" ||
    pathname === "/api/hackerone/connection-test" ||
    pathname === "/api/hackerone/programs/synchronize" ||
    pathname === "/api/hackerone/program/select" ||
    pathname === "/api/hackerone/program/synchronize" ||
    pathname === "/api/hackerone/campaign/bind" ||
    pathname === "/api/hackerone/policy/accept" ||
    pathname === "/api/hackerone/manual-import" ||
    pathname === "/api/programs/import" ||
    pathname === "/api/simulation/run" ||
    pathname === "/api/approvals/decide" ||
    pathname === "/api/kill-switch/engage" ||
    pathname === "/api/kill-switch/clear"
  );
}

function requireActiveTesting(
  dependencies: DashboardDependencies,
): LocalActiveTestingController {
  if (!isTrustedLocalActiveTestingController(dependencies.activeTesting))
    throw new SecurityError("ACTIVE_TESTING_CONTROLLER_UNAVAILABLE");
  return dependencies.activeTesting;
}

function parseActiveTestingPlanPreparation(value: unknown): {
  readonly programRef: string;
  readonly snapshotDigest: string;
  readonly scopeId: string;
  readonly assetIdentifierDigest: string;
  readonly testClass: "cors_preflight" | "http_headers" | "security_txt";
  readonly confirmations: {
    readonly automationPermissionReviewed: true;
    readonly scopeInstructionReviewed: true;
    readonly scopeExclusionsReviewed: true;
    readonly noSideEffectsConfirmed: true;
  };
} {
  assertExactObject(
    value,
    [
      "assetIdentifierDigest",
      "confirmations",
      "programRef",
      "scopeId",
      "snapshotDigest",
      "testClass",
    ],
    "ACTIVE_TESTING_DASHBOARD_PLAN_INVALID",
  );
  const confirmations = value["confirmations"];
  assertExactObject(
    confirmations,
    [
      "automationPermissionReviewed",
      "noSideEffectsConfirmed",
      "scopeExclusionsReviewed",
      "scopeInstructionReviewed",
    ],
    "ACTIVE_TESTING_DASHBOARD_PLAN_INVALID",
  );
  const programRef = value["programRef"];
  const snapshotDigest = value["snapshotDigest"];
  const scopeId = value["scopeId"];
  const assetIdentifierDigest = value["assetIdentifierDigest"];
  const testClass = value["testClass"];
  if (
    typeof programRef !== "string" ||
    !/^h1a_[a-f0-9]{64}$/u.test(programRef) ||
    typeof snapshotDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(snapshotDigest) ||
    typeof scopeId !== "string" ||
    !/^[A-Za-z0-9._-]{1,128}$/u.test(scopeId) ||
    typeof assetIdentifierDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(assetIdentifierDigest) ||
    !(
      testClass === "cors_preflight" ||
      testClass === "http_headers" ||
      testClass === "security_txt"
    ) ||
    confirmations["automationPermissionReviewed"] !== true ||
    confirmations["scopeInstructionReviewed"] !== true ||
    confirmations["scopeExclusionsReviewed"] !== true ||
    confirmations["noSideEffectsConfirmed"] !== true
  )
    throw new SecurityError("ACTIVE_TESTING_DASHBOARD_PLAN_INVALID");
  return Object.freeze({
    programRef,
    snapshotDigest,
    scopeId,
    assetIdentifierDigest,
    testClass,
    confirmations: Object.freeze({
      automationPermissionReviewed: true as const,
      scopeInstructionReviewed: true as const,
      scopeExclusionsReviewed: true as const,
      noSideEffectsConfirmed: true as const,
    }),
  });
}

function parseActiveTestingPlanAction(value: unknown): {
  readonly approvalId: string;
  readonly planId: string;
  readonly confirmed: true;
} {
  assertExactObject(
    value,
    ["approvalId", "confirmed", "planId"],
    "ACTIVE_TESTING_DASHBOARD_ACTION_INVALID",
  );
  const approvalId = value["approvalId"];
  const planId = value["planId"];
  if (
    value["confirmed"] !== true ||
    typeof approvalId !== "string" ||
    !/^[A-Za-z0-9._-]{1,128}$/u.test(approvalId) ||
    typeof planId !== "string" ||
    !/^[A-Za-z0-9._-]{1,128}$/u.test(planId)
  )
    throw new SecurityError("ACTIVE_TESTING_DASHBOARD_ACTION_INVALID");
  return Object.freeze({ approvalId, planId, confirmed: true as const });
}

function requireCoreProvisioning(
  dependencies: DashboardDependencies,
): LocalCoreProvisioningController {
  if (!isTrustedCoreProvisioningController(dependencies.coreProvisioning))
    throw new SecurityError("CORE_PROVISIONING_UNAVAILABLE");
  return dependencies.coreProvisioning;
}

function requireHackerOne(
  dependencies: DashboardDependencies,
): HackerOneMetadataService {
  if (dependencies.hackerOne === undefined)
    throw new SecurityError("HACKERONE_SERVICE_UNAVAILABLE");
  return dependencies.hackerOne;
}

function parseHackerOneProgramReference(value: unknown): {
  readonly programRef: string;
} {
  assertExactObject(
    value,
    ["programRef"],
    "HACKERONE_DASHBOARD_PROGRAM_REF_INVALID",
  );
  const programRef = value["programRef"];
  if (
    typeof programRef !== "string" ||
    !/^h1[am]_[0-9a-f]{64}$/u.test(programRef)
  )
    throw new SecurityError("HACKERONE_DASHBOARD_PROGRAM_REF_INVALID");
  return Object.freeze({ programRef });
}

function parseHackerOnePolicyAcceptance(value: unknown): {
  readonly programRef: string;
  readonly snapshotDigest: string;
} {
  assertExactObject(
    value,
    ["confirmed", "programRef", "snapshotDigest"],
    "HACKERONE_DASHBOARD_POLICY_ACCEPTANCE_INVALID",
  );
  const programRef = value["programRef"];
  const snapshotDigest = value["snapshotDigest"];
  if (
    value["confirmed"] !== true ||
    typeof programRef !== "string" ||
    !/^h1[am]_[0-9a-f]{64}$/u.test(programRef) ||
    typeof snapshotDigest !== "string" ||
    !/^[0-9a-f]{64}$/u.test(snapshotDigest)
  )
    throw new SecurityError("HACKERONE_DASHBOARD_POLICY_ACCEPTANCE_INVALID");
  return Object.freeze({ programRef, snapshotDigest });
}

function parseHackerOneCampaignBinding(value: unknown): {
  readonly programRef: string;
  readonly campaignId: string;
} {
  assertExactObject(
    value,
    ["campaignId", "programRef"],
    "HACKERONE_DASHBOARD_CAMPAIGN_BINDING_INVALID",
  );
  const programRef = value["programRef"];
  const campaignId = value["campaignId"];
  if (
    typeof programRef !== "string" ||
    !/^h1[am]_[0-9a-f]{64}$/u.test(programRef) ||
    typeof campaignId !== "string" ||
    !/^[A-Za-z0-9_-]{1,128}$/u.test(campaignId)
  )
    throw new SecurityError("HACKERONE_DASHBOARD_CAMPAIGN_BINDING_INVALID");
  return Object.freeze({ programRef, campaignId });
}

function parseHackerOneManualImport(value: unknown): {
  readonly source: string;
} {
  assertExactObject(
    value,
    ["source"],
    "HACKERONE_DASHBOARD_MANUAL_IMPORT_INVALID",
  );
  const source = value["source"];
  if (
    typeof source !== "string" ||
    source.length < 1 ||
    Buffer.byteLength(source, "utf8") > MAX_HACKERONE_MANUAL_IMPORT_SOURCE_BYTES
  )
    throw new SecurityError("HACKERONE_DASHBOARD_MANUAL_IMPORT_INVALID");
  return Object.freeze({ source });
}

function assertEmptyObject(value: unknown, code: string): void {
  assertExactObject(value, [], code);
}

function parseApprovalDecisionRequest(
  value: unknown,
): DashboardApprovalDecisionInput {
  assertExactObject(
    value,
    [
      "actor",
      "decision",
      "expectedPayloadHash",
      "expectedRevision",
      "id",
      "userAction",
    ],
    "DASHBOARD_APPROVAL_DECISION_INVALID",
  );
  const actor = value["actor"];
  const decision = value["decision"];
  const expectedPayloadHash = value["expectedPayloadHash"];
  const expectedRevision = value["expectedRevision"];
  const id = value["id"];
  const userAction = value["userAction"];
  if (
    typeof actor !== "string" ||
    !ACTOR.test(actor) ||
    (decision !== "accepted" && decision !== "rejected") ||
    typeof expectedPayloadHash !== "string" ||
    !/^[a-f0-9]{64}$/u.test(expectedPayloadHash) ||
    expectedRevision !== 0 ||
    typeof id !== "string" ||
    !/^[A-Za-z0-9_-]{1,128}$/u.test(id) ||
    typeof userAction !== "string" ||
    userAction.trim().length === 0 ||
    userAction.length > 500
  )
    throw new SecurityError("DASHBOARD_APPROVAL_DECISION_INVALID");
  return Object.freeze({
    id,
    expectedRevision,
    expectedPayloadHash,
    decision,
    actor,
    userAction: userAction.trim(),
  });
}

function requireOperatorSigner(
  dependencies: DashboardDependencies,
): OperatorSigner {
  const signer = dependencies.operatorSigner;
  if (!isTrustedOperatorSigner(signer))
    throw new SecurityError("OPERATOR_SIGNER_REQUIRED");
  return signer;
}

function assertSignerMatchesActor(signer: OperatorSigner, actor: string): void {
  if (signer.credential.operator_id !== actor)
    throw new SecurityError("OPERATOR_IDENTITY_MISMATCH");
}

function ensureOperatorEnrolled(
  store: ControlPlaneStore,
  signer: OperatorSigner,
  sessionId: string,
  at: string,
): void {
  const current = store.getLocalOperatorCredential();
  if (current !== undefined) {
    if (
      current.operator_id !== signer.credential.operator_id ||
      current.public_key_spki_base64url !==
        signer.credential.public_key_spki_base64url ||
      current.key_fingerprint_sha256 !==
        signer.credential.key_fingerprint_sha256 ||
      current.key_revision !== signer.credential.key_revision
    )
      throw new SecurityError("OPERATOR_CREDENTIAL_MISMATCH");
  }
  const proof = signer.signEnrollment({
    controlPlaneId: store.getControlPlaneId(),
    sessionId,
    nonce: randomBytes(32).toString("base64url"),
    issuedAt: at,
    expiresAt: operatorStatementExpiry(at),
  });
  if (current === undefined) store.enrollLocalOperator(proof);
  else store.authenticateLocalOperatorSession(proof);
}

function clearKillSwitchWithSigner(
  dependencies: DashboardDependencies,
  sessionId: string,
  actor: string,
  at: string,
): { readonly active: false; readonly revision: number } {
  const signer = requireOperatorSigner(dependencies);
  assertSignerMatchesActor(signer, actor);
  ensureOperatorEnrolled(dependencies.store, signer, sessionId, at);
  const context = dependencies.store.describeKillSwitchClear();
  return dependencies.store.clearKillSwitch(
    signer.signKillSwitchClear({
      controlPlaneId: context.controlPlaneId,
      expectedRevision: context.expectedRevision,
      userAction: "explicit_local_dashboard_kill_switch_clear",
      contextDigestSha256: context.contextDigestSha256,
      sessionId,
      nonce: randomBytes(32).toString("base64url"),
      issuedAt: at,
      expiresAt: operatorStatementExpiry(at),
    }),
  );
}

function decideDashboardApproval(
  store: ControlPlaneStore,
  signer: OperatorSigner,
  sessionId: string,
  approvalId: string,
  decision: "accepted" | "rejected",
  userAction: string,
  at: string,
): ApprovalRecord {
  const context = store.describeApprovalDecision(approvalId);
  return store.decideApproval(
    signer.signApprovalDecision({
      controlPlaneId: context.controlPlaneId,
      approvalId: context.approvalId,
      approvalKind: context.approvalKind,
      approvalPayloadHashSha256: context.approvalPayloadHashSha256,
      expectedRevision: context.expectedRevision,
      decision,
      userAction,
      contextDigestSha256: context.contextDigestSha256,
      sessionId,
      nonce: randomBytes(32).toString("base64url"),
      issuedAt: at,
      expiresAt: operatorStatementExpiry(at),
    }),
  );
}

function operatorStatementExpiry(issuedAt: string): string {
  const milliseconds = Date.parse(issuedAt);
  if (!Number.isFinite(milliseconds))
    throw new SecurityError("OPERATOR_STATEMENT_TIME_INVALID");
  return new Date(milliseconds + 5 * 60 * 1_000).toISOString();
}

function assertMutationHeaders(
  request: IncomingMessage,
  origin: string,
  csrfToken: string,
  maximumBodyBytes: number,
): void {
  if (request.headers.origin !== origin)
    throw new DashboardHttpError(403, "DASHBOARD_ORIGIN_BLOCKED");
  const supplied = request.headers["x-csrf-token"];
  if (typeof supplied !== "string" || !safeEqual(supplied, csrfToken))
    throw new DashboardHttpError(403, "DASHBOARD_CSRF_BLOCKED");
  const contentType = request.headers["content-type"];
  if (typeof contentType !== "string")
    throw new DashboardHttpError(415, "DASHBOARD_CONTENT_TYPE_BLOCKED");
  if (contentType.split(";", 1)[0]?.trim().toLowerCase() !== "application/json")
    throw new DashboardHttpError(415, "DASHBOARD_CONTENT_TYPE_BLOCKED");
  const length = request.headers["content-length"];
  if (length !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(length))
      throw new DashboardHttpError(400, "DASHBOARD_CONTENT_LENGTH_INVALID");
    if (Number(length) > maximumBodyBytes)
      throw new DashboardHttpError(413, "DASHBOARD_BODY_TOO_LARGE");
  }
}

function assertCredentialMutationHeaders(
  request: IncomingMessage,
  origin: string,
  csrfToken: string,
): number {
  if (request.headers.origin !== origin)
    throw new DashboardHttpError(403, "DASHBOARD_ORIGIN_BLOCKED");
  const supplied = request.headers["x-csrf-token"];
  if (typeof supplied !== "string" || !safeEqual(supplied, csrfToken))
    throw new DashboardHttpError(403, "DASHBOARD_CSRF_BLOCKED");
  if (request.headers["content-type"] !== "application/octet-stream")
    throw new DashboardHttpError(415, "DASHBOARD_CONTENT_TYPE_BLOCKED");
  const length = request.headers["content-length"];
  if (
    typeof length !== "string" ||
    !/^[1-9][0-9]*$/u.test(length) ||
    !Number.isSafeInteger(Number(length))
  )
    throw new DashboardHttpError(400, "DASHBOARD_CONTENT_LENGTH_INVALID");
  const parsed = Number(length);
  if (parsed > MAX_HACKERONE_CREDENTIAL_FRAME_BYTES)
    throw new DashboardHttpError(413, "DASHBOARD_BODY_TOO_LARGE");
  return parsed;
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.byteLength === rightBytes.byteLength &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function readJsonBody(
  request: IncomingMessage,
  maximumBodyBytes: number,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const cleanup = (): void => {
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onAborted);
    };
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onData = (chunk: unknown): void => {
      if (settled) return;
      if (!Buffer.isBuffer(chunk)) {
        fail(new DashboardHttpError(400, "DASHBOARD_BODY_INVALID"));
        return;
      }
      bytes += chunk.byteLength;
      if (bytes > maximumBodyBytes) {
        fail(new DashboardHttpError(413, "DASHBOARD_BODY_TOO_LARGE"));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      try {
        const source = new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.concat(chunks),
        );
        const document = parseDocument(source, {
          merge: false,
          uniqueKeys: true,
          version: "1.2",
        });
        if (document.errors.length > 0 || document.warnings.length > 0)
          throw new Error("DASHBOARD_JSON_AMBIGUOUS");
        resolve(JSON.parse(source) as unknown);
      } catch {
        reject(new DashboardHttpError(400, "DASHBOARD_JSON_INVALID"));
      }
    };
    const onError = (): void => {
      fail(new DashboardHttpError(400, "DASHBOARD_BODY_READ_FAILED"));
    };
    const onAborted = (): void => {
      fail(new DashboardHttpError(400, "DASHBOARD_BODY_ABORTED"));
    };
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onAborted);
  });
}

function readBoundedCredentialBody(
  request: IncomingMessage,
  declaredLength: number,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let failure: DashboardHttpError | undefined;
    let settled = false;
    const eraseChunks = (): void => {
      for (const chunk of chunks) chunk.fill(0);
      chunks.length = 0;
    };
    const cleanup = (): void => {
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onAborted);
    };
    const fail = (error: DashboardHttpError): void => {
      if (settled) return;
      settled = true;
      cleanup();
      eraseChunks();
      reject(error);
    };
    const onData = (chunk: unknown): void => {
      if (!Buffer.isBuffer(chunk)) {
        failure ??= new DashboardHttpError(400, "DASHBOARD_BODY_INVALID");
        return;
      }
      let copy: Buffer | undefined;
      try {
        if (failure !== undefined) return;
        bytes += chunk.byteLength;
        if (
          bytes > declaredLength ||
          bytes > MAX_HACKERONE_CREDENTIAL_FRAME_BYTES
        ) {
          failure = new DashboardHttpError(
            bytes > MAX_HACKERONE_CREDENTIAL_FRAME_BYTES ? 413 : 400,
            bytes > MAX_HACKERONE_CREDENTIAL_FRAME_BYTES
              ? "DASHBOARD_BODY_TOO_LARGE"
              : "DASHBOARD_CONTENT_LENGTH_INVALID",
          );
          eraseChunks();
          return;
        }
        copy = Buffer.from(chunk);
        chunks.push(copy);
        copy = undefined;
      } finally {
        copy?.fill(0);
        chunk.fill(0);
      }
    };
    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (failure !== undefined || bytes !== declaredLength) {
        eraseChunks();
        reject(
          failure ??
            new DashboardHttpError(400, "DASHBOARD_CONTENT_LENGTH_INVALID"),
        );
        return;
      }
      let payload: Buffer | undefined;
      try {
        payload = Buffer.concat(chunks, bytes);
        resolve(payload);
        payload = undefined;
      } catch {
        reject(new DashboardHttpError(400, "DASHBOARD_BODY_INVALID"));
      } finally {
        payload?.fill(0);
        eraseChunks();
      }
    };
    const onError = (): void => {
      fail(new DashboardHttpError(400, "DASHBOARD_BODY_READ_FAILED"));
    };
    const onAborted = (): void => {
      fail(new DashboardHttpError(400, "DASHBOARD_BODY_ABORTED"));
    };
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onAborted);
  });
}

function parseHackerOneCredentialFrame(payload: Uint8Array): {
  readonly identifier: Uint8Array;
  readonly token: Uint8Array;
} {
  if (
    payload.byteLength < HACKERONE_CREDENTIAL_FRAME_HEADER_BYTES ||
    HACKERONE_CREDENTIAL_FRAME_MAGIC.some(
      (expected, index) => payload[index] !== expected,
    ) ||
    payload[4] !== HACKERONE_CREDENTIAL_FRAME_VERSION
  )
    throw new SecurityError("HACKERONE_CREDENTIAL_FRAME_INVALID");
  const view = new DataView(
    payload.buffer,
    payload.byteOffset,
    HACKERONE_CREDENTIAL_FRAME_HEADER_BYTES,
  );
  const identifierLength = view.getUint16(5, false);
  const tokenLength = view.getUint16(7, false);
  if (
    identifierLength < 1 ||
    identifierLength > MAX_HACKERONE_CREDENTIAL_BYTES ||
    tokenLength < 1 ||
    tokenLength > MAX_HACKERONE_CREDENTIAL_BYTES ||
    payload.byteLength !==
      HACKERONE_CREDENTIAL_FRAME_HEADER_BYTES + identifierLength + tokenLength
  )
    throw new SecurityError("HACKERONE_CREDENTIAL_FRAME_INVALID");
  const identifier = payload.subarray(
    HACKERONE_CREDENTIAL_FRAME_HEADER_BYTES,
    HACKERONE_CREDENTIAL_FRAME_HEADER_BYTES + identifierLength,
  );
  const token = payload.subarray(
    HACKERONE_CREDENTIAL_FRAME_HEADER_BYTES + identifierLength,
  );
  if (!isPrintableCredential(identifier) || !isPrintableCredential(token))
    throw new SecurityError("HACKERONE_CREDENTIAL_FRAME_INVALID");
  return Object.freeze({ identifier, token });
}

function isPrintableCredential(value: Uint8Array): boolean {
  return value.every((byte) => byte >= 0x21 && byte <= 0x7e);
}

function parseImportRequest(value: unknown): {
  readonly format: "json" | "yaml";
  readonly source: string;
} {
  assertExactObject(value, ["format", "source"], "DASHBOARD_IMPORT_INVALID");
  const format = value["format"];
  const source = value["source"];
  if ((format !== "json" && format !== "yaml") || typeof source !== "string")
    throw new SecurityError("DASHBOARD_IMPORT_INVALID");
  return Object.freeze({ format, source });
}

function parseSimulationRequest(
  value: unknown,
  confirmedAt: string,
): HumanSimulationEvidence {
  assertExactObject(
    value,
    ["actor", "confirmations", "confirmationTimes", "reviewDigest"],
    "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
  );
  const actor = value["actor"];
  const confirmations = value["confirmations"];
  const confirmationTimes = value["confirmationTimes"];
  const reviewDigest = value["reviewDigest"];
  if (typeof actor !== "string" || !ACTOR.test(actor))
    throw new SecurityError("DASHBOARD_SIMULATION_ACTOR_INVALID");
  assertExactObject(
    confirmations,
    CONFIRMATION_KEYS,
    "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
  );
  if (CONFIRMATION_KEYS.some((key) => confirmations[key] !== true))
    throw new SecurityError("DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID");
  assertExactObject(
    confirmationTimes,
    CONFIRMATION_KEYS,
    "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
  );
  if (typeof reviewDigest !== "string" || !/^[a-f0-9]{64}$/u.test(reviewDigest))
    throw new SecurityError("DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID");
  return Object.freeze({
    version: 2,
    actor,
    confirmedAt,
    reviewDigest,
    confirmations: Object.freeze({
      clearKillSwitch: true,
      acceptPolicyV1: true,
      approveCampaignV1: true,
      acceptPolicyV2: true,
      approveCampaignV2: true,
      queueReportReview: true,
    }),
    confirmationTimes: Object.freeze({
      clearKillSwitch: requireStringField(
        confirmationTimes,
        "clearKillSwitch",
        "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
      ),
      acceptPolicyV1: requireStringField(
        confirmationTimes,
        "acceptPolicyV1",
        "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
      ),
      approveCampaignV1: requireStringField(
        confirmationTimes,
        "approveCampaignV1",
        "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
      ),
      acceptPolicyV2: requireStringField(
        confirmationTimes,
        "acceptPolicyV2",
        "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
      ),
      approveCampaignV2: requireStringField(
        confirmationTimes,
        "approveCampaignV2",
        "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
      ),
      queueReportReview: requireStringField(
        confirmationTimes,
        "queueReportReview",
        "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
      ),
    }),
  });
}

function requireStringField(
  value: Readonly<Record<string, unknown>>,
  key: string,
  code: string,
): string {
  const field = value[key];
  if (typeof field !== "string") throw new SecurityError(code);
  return field;
}

function parseKillSwitchRequest(value: unknown): { readonly actor: string } {
  assertExactObject(
    value,
    ["actor", "confirmed"],
    "DASHBOARD_KILL_SWITCH_CONFIRMATION_INVALID",
  );
  const actor = value["actor"];
  if (
    value["confirmed"] !== true ||
    typeof actor !== "string" ||
    !ACTOR.test(actor)
  )
    throw new SecurityError("DASHBOARD_KILL_SWITCH_CONFIRMATION_INVALID");
  return Object.freeze({ actor });
}

function assertExactObject(
  value: unknown,
  expectedKeys: readonly string[],
  code: string,
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new SecurityError(code);
  const keys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  )
    throw new SecurityError(code);
}

function timestamp(now: () => Date): string {
  const value = now();
  if (!Number.isFinite(value.getTime()))
    throw new SecurityError("DASHBOARD_CLOCK_INVALID");
  return value.toISOString();
}

function applySecurityHeaders(response: ServerResponse): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS))
    response.setHeader(name, value);
}

function sendJson(
  response: ServerResponse,
  statusCode: number,
  value: unknown,
): void {
  sendText(
    response,
    statusCode,
    "application/json; charset=utf-8",
    JSON.stringify(value),
  );
}

function sendError(response: ServerResponse, error: unknown): void {
  if (error instanceof DashboardHttpError) {
    sendJson(response, error.statusCode, { error: error.code });
    return;
  }
  if (error instanceof SecurityError) {
    sendJson(response, 409, { error: error.code });
    return;
  }
  sendJson(response, 500, { error: errorCode(error) });
}

function sendText(
  response: ServerResponse,
  statusCode: number,
  contentType: string,
  body: string,
): void {
  response.statusCode = statusCode;
  response.setHeader("connection", "close");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.setHeader("content-type", contentType);
  response.end(body);
}

function isLoopbackAddress(
  address: string | AddressInfo | null,
): address is AddressInfo {
  return (
    address !== null &&
    typeof address !== "string" &&
    address.address === LOOPBACK_HOST &&
    address.family === "IPv4"
  );
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ exclusive: true, host: LOOPBACK_HOST, port });
  });
}

function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
    server.closeIdleConnections();
  });
}

class DashboardHttpError extends Error {
  public constructor(
    public readonly statusCode: number,
    public readonly code: string,
  ) {
    super(code);
    this.name = "DashboardHttpError";
  }
}
