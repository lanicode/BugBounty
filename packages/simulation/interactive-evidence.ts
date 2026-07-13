import { SecurityError } from "../shared/errors.js";
import {
  SIMULATION_CONFIRMATION_ORDER,
  type HumanSimulationEvidence,
  type SimulationConfirmationKey,
} from "./orchestrator.js";

const PROMPTS: Readonly<Record<SimulationConfirmationKey, string>> =
  Object.freeze({
    clearKillSwitch:
      "Kill Switch nur fuer diesen lokalen Simulationslauf freigeben?",
    acceptPolicyV1:
      "Angezeigte lokale Policy v1 samt Hash ausdruecklich akzeptieren?",
    approveCampaignV1:
      "Angezeigten lokalen Kampagnenvertrag v1 ausdruecklich freigeben?",
    acceptPolicyV2:
      "Policy v2 nach Pruefung des angezeigten Drift-Diffs akzeptieren?",
    approveCampaignV2:
      "Angezeigten lokalen Kampagnenvertrag v2 ausdruecklich freigeben?",
    queueReportReview:
      "Report-Entwurf nur zur lokalen menschlichen Review einreihen?",
  });

export async function collectInteractiveSimulationEvidence(input: {
  readonly reviewDigest: string;
  readonly prompt: (message: string) => Promise<string>;
  readonly now: () => Date;
}): Promise<HumanSimulationEvidence> {
  const actor = (await input.prompt("Lokaler Akteur: ")).trim();
  const times = new Map<SimulationConfirmationKey, string>();
  let lastTime = Number.NEGATIVE_INFINITY;
  for (const key of SIMULATION_CONFIRMATION_ORDER) {
    const answer = (await input.prompt(`${PROMPTS[key]} [yes/NO]: `)).trim();
    if (answer !== "yes")
      throw new SecurityError("SIMULATION_CONFIRMATION_DECLINED");
    const timestamp = Math.max(input.now().getTime(), lastTime + 1);
    lastTime = timestamp;
    times.set(key, new Date(timestamp).toISOString());
  }
  const confirmedAt = Math.max(input.now().getTime(), lastTime);
  return Object.freeze({
    version: 2,
    actor,
    confirmedAt: new Date(confirmedAt).toISOString(),
    reviewDigest: input.reviewDigest,
    confirmations: Object.freeze({
      clearKillSwitch: true,
      acceptPolicyV1: true,
      approveCampaignV1: true,
      acceptPolicyV2: true,
      approveCampaignV2: true,
      queueReportReview: true,
    }),
    confirmationTimes: Object.freeze({
      clearKillSwitch: requireTime(times, "clearKillSwitch"),
      acceptPolicyV1: requireTime(times, "acceptPolicyV1"),
      approveCampaignV1: requireTime(times, "approveCampaignV1"),
      acceptPolicyV2: requireTime(times, "acceptPolicyV2"),
      approveCampaignV2: requireTime(times, "approveCampaignV2"),
      queueReportReview: requireTime(times, "queueReportReview"),
    }),
  });
}

function requireTime(
  values: ReadonlyMap<SimulationConfirmationKey, string>,
  key: SimulationConfirmationKey,
): string {
  const value = values.get(key);
  if (value === undefined)
    throw new SecurityError("SIMULATION_EVIDENCE_INVALID");
  return value;
}
