import { expect, test as base } from "playwright/test";
import {
  proveForeignLoopbackPortBlocked,
  runLocalDemoJourney,
  type BlockedLoopbackProbe,
} from "../support/local-demo-harness.js";
import type { JourneyEvidence, JourneyRole } from "../support/journey-model.js";

interface LocalDemoFixtures {
  readonly runJourney: (role: JourneyRole) => Promise<JourneyEvidence>;
  readonly proveForeignPortBlocked: () => Promise<BlockedLoopbackProbe>;
}

export const test = base.extend<LocalDemoFixtures>({
  runJourney: async ({ browser }, use) => {
    await use((role) => runLocalDemoJourney(browser, role));
  },
  proveForeignPortBlocked: async ({ browser }, use) => {
    await use(() => proveForeignLoopbackPortBlocked(browser));
  },
});

export { expect };
