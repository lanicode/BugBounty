import { describe, expect, it } from "vitest";
import { parseEventKeyMinimumVersion } from "../../packages/event-key-lifecycle/index.js";

describe("event key minimum-version configuration", () => {
  it.each(["1", "2", "9999", "10000"])(
    "accepts the explicit valid value %s",
    (value) => {
      expect(parseEventKeyMinimumVersion(value)).toBe(Number(value));
    },
  );

  it.each([
    undefined,
    null,
    1,
    "",
    "0",
    "01",
    "+1",
    " 1",
    "1 ",
    "1.0",
    "10001",
    "999999",
  ])("fails closed for missing or invalid value %j", (value) => {
    expect(() => parseEventKeyMinimumVersion(value)).toThrow(
      "EVENT_KEY_MIN_VERSION_CONFIG_INVALID",
    );
  });
});
