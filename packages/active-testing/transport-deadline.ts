import { SecurityError } from "../shared/errors.js";

const MAX_OPERATION_TIMEOUT_MS = 10_000;
const KILL_SWITCH_POLL_MS = 100;

export function activeTestRemainingTimeoutMs(
  configuredTimeoutMs: number,
  monotonicElapsedMs: number,
): number {
  if (
    !Number.isSafeInteger(configuredTimeoutMs) ||
    configuredTimeoutMs < 1 ||
    configuredTimeoutMs > MAX_OPERATION_TIMEOUT_MS ||
    !Number.isFinite(monotonicElapsedMs) ||
    monotonicElapsedMs < 0
  )
    throw new SecurityError("ACTIVE_TEST_TRANSPORT_DEADLINE_INVALID");
  return Math.max(
    0,
    Math.min(
      configuredTimeoutMs,
      Math.floor(configuredTimeoutMs - monotonicElapsedMs),
    ),
  );
}

export function activeTestBoundedDurationMs(
  configuredTimeoutMs: number,
  monotonicElapsedMs: number,
): number {
  if (
    !Number.isSafeInteger(configuredTimeoutMs) ||
    configuredTimeoutMs < 1 ||
    configuredTimeoutMs > MAX_OPERATION_TIMEOUT_MS ||
    !Number.isFinite(monotonicElapsedMs) ||
    monotonicElapsedMs < 0
  )
    throw new SecurityError("ACTIVE_TEST_TRANSPORT_DEADLINE_INVALID");
  return Math.max(
    0,
    Math.min(configuredTimeoutMs, Math.floor(monotonicElapsedMs)),
  );
}

/**
 * Internal transport boundary used to place asynchronous prerequisites such as
 * DNS resolution under the same fail-closed deadline and kill-switch polling
 * as the HTTP request. It is intentionally not exported from the package
 * barrel and does not make a resolver injectable into the production runner.
 */
export function awaitActiveTestTransportOperation<T>(
  operation: () => PromiseLike<T>,
  timeoutMs: number,
  assertKillSwitchClear: () => void,
  operationFailureCode: string,
): Promise<T> {
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > MAX_OPERATION_TIMEOUT_MS ||
    typeof operation !== "function" ||
    typeof assertKillSwitchClear !== "function" ||
    !/^ACTIVE_TEST_[A-Z0-9_]+$/u.test(operationFailureCode)
  )
    return Promise.reject(
      new SecurityError("ACTIVE_TEST_TRANSPORT_DEADLINE_INVALID"),
    );

  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    const clear = (): void => {
      clearTimeout(deadline);
      clearInterval(killSwitchPoll);
    };
    const finishError = (code: string): void => {
      if (settled) return;
      settled = true;
      clear();
      rejectPromise(new SecurityError(code));
    };
    const finishSuccess = (value: T): void => {
      if (settled) return;
      settled = true;
      clear();
      resolvePromise(value);
    };
    const deadline = setTimeout(() => {
      finishError("ACTIVE_TEST_REQUEST_TIMEOUT");
    }, timeoutMs);
    deadline.unref();
    const killSwitchPoll = setInterval(
      () => {
        try {
          assertKillSwitchClear();
        } catch {
          finishError("ACTIVE_TEST_KILL_SWITCH");
        }
      },
      Math.min(KILL_SWITCH_POLL_MS, timeoutMs),
    );
    killSwitchPoll.unref();

    try {
      assertKillSwitchClear();
    } catch {
      finishError("ACTIVE_TEST_KILL_SWITCH");
      return;
    }
    let pending: PromiseLike<T>;
    try {
      pending = operation();
    } catch {
      finishError(operationFailureCode);
      return;
    }
    void Promise.resolve(pending).then(
      (value) => {
        if (settled) return;
        try {
          assertKillSwitchClear();
          finishSuccess(value);
        } catch {
          finishError("ACTIVE_TEST_KILL_SWITCH");
        }
      },
      () => {
        finishError(operationFailureCode);
      },
    );
  });
}
