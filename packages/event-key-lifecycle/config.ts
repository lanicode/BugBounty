import { MAX_EVENT_KEY_VERSION } from "../event-store/index.js";
import { SecurityError } from "../shared/errors.js";

export function parseEventKeyMinimumVersion(value: unknown): number {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,4}$/u.test(value))
    throw new SecurityError("EVENT_KEY_MIN_VERSION_CONFIG_INVALID");
  const version = Number(value);
  if (!Number.isSafeInteger(version) || version > MAX_EVENT_KEY_VERSION)
    throw new SecurityError("EVENT_KEY_MIN_VERSION_CONFIG_INVALID");
  return version;
}
