import { describe, expect, it } from "vitest";
import {
  createInitialHackerOneMetadataRequestPlan,
  createNextHackerOneMetadataRequestPlan,
  HACKERONE_METADATA_MAX_PAGE_SIZE,
  isStrongHackerOneProgramHandle,
} from "../../../packages/hackerone-readonly/request-policy.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  resolveHackerOneMetadataReadRuntime,
  type HackerOneMetadataReadRuntimeState,
} from "../../../packages/hackerone-readonly/runtime.js";
import {
  HACKERONE_API_HOST,
  HACKERONE_API_ORIGIN,
  HACKERONE_API_PORT,
} from "../../../packages/hackerone-readonly/types.js";

function runtime(
  maximum = 10,
  perMinute = 5,
): HackerOneMetadataReadRuntimeState {
  return resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    external_integrations_enabled: true,
    enabled: true,
    request_budget: {
      max_requests_total: maximum,
      requests_per_minute: perMinute,
      max_concurrency: 1,
    },
  });
}

function budget(
  overrides: Partial<{
    activeRequests: number;
    consumedRequests: number;
    requestsInCurrentMinute: number;
  }> = {},
): {
  activeRequests: number;
  consumedRequests: number;
  requestsInCurrentMinute: number;
} {
  return {
    consumedRequests: 0,
    activeRequests: 0,
    requestsInCurrentMinute: 0,
    ...overrides,
  };
}

function intent(
  operation:
    | "program"
    | "programs"
    | "scope_exclusions"
    | "structured_scopes" = "programs",
): Record<string, unknown> {
  const requiresHandle = operation !== "programs";
  return {
    version: 1,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    operation,
    handle: requiresHandle ? "synthetic-program" : null,
    page:
      operation === "program"
        ? null
        : {
            number: 1,
            size: 10,
          },
  };
}

describe("HackerOne metadata request plans", () => {
  it("builds the exact one-request connection-test plan", () => {
    const value = intent("programs");
    value["page"] = { number: 1, size: 1 };
    const plan = createInitialHackerOneMetadataRequestPlan(
      value,
      runtime(),
      budget(),
    );

    expect(plan).toEqual({
      version: 1,
      capability: "HACKERONE_METADATA_READ",
      operation: "programs",
      method: "GET",
      scheme: "https",
      host: HACKERONE_API_HOST,
      port: HACKERONE_API_PORT,
      origin: HACKERONE_API_ORIGIN,
      path: "/v1/hackers/programs",
      query: "?page[number]=1&page[size]=1",
      url: `${HACKERONE_API_ORIGIN}/v1/hackers/programs?page[number]=1&page[size]=1`,
      handle: null,
      page: { number: 1, size: 1 },
      captureMode: "metadata_only",
      followRedirects: false,
      budgetUnits: 1,
    });
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.page)).toBe(true);
    expect(plan).not.toHaveProperty("body");
    expect(plan).not.toHaveProperty("headers");
    expect(plan).not.toHaveProperty("redirect");
  });

  it.each([
    ["programs", null, "/v1/hackers/programs", "?page[number]=1&page[size]=10"],
    [
      "program",
      "synthetic-program",
      "/v1/hackers/programs/synthetic-program",
      "",
    ],
    [
      "structured_scopes",
      "synthetic-program",
      "/v1/hackers/programs/synthetic-program/structured_scopes",
      "?page[number]=1&page[size]=10",
    ],
    [
      "scope_exclusions",
      "synthetic-program",
      "/v1/hackers/programs/synthetic-program/scope_exclusions",
      "?page[number]=1&page[size]=10",
    ],
  ] as const)(
    "maps only the %s operation to its fixed endpoint",
    (operation, expectedHandle, expectedPath, expectedQuery) => {
      const plan = createInitialHackerOneMetadataRequestPlan(
        intent(operation),
        runtime(),
        budget(),
      );
      expect(plan.operation).toBe(operation);
      expect(plan.handle).toBe(expectedHandle);
      expect(plan.path).toBe(expectedPath);
      expect(plan.query).toBe(expectedQuery);
      expect(plan.url).toBe(
        `${HACKERONE_API_ORIGIN}${expectedPath}${expectedQuery}`,
      );
      expect(plan.method).toBe("GET");
      expect(plan.followRedirects).toBe(false);
    },
  );

  it("accepts the bounded maximum page size", () => {
    const value = intent("programs");
    value["page"] = {
      number: 1,
      size: HACKERONE_METADATA_MAX_PAGE_SIZE,
    };
    expect(
      createInitialHackerOneMetadataRequestPlan(value, runtime(), budget())
        .page,
    ).toEqual({ number: 1, size: 100 });
  });

  it.each([
    ["unknown operation", { ...intent(), operation: "weaknesses" }],
    ["write-like operation", { ...intent(), operation: "report_submit" }],
    ["wrong version", { ...intent(), version: 2 }],
    ["wrong capability", { ...intent(), capability: "TARGET_REQUEST" }],
    ["unknown key", { ...intent(), url: "https://synthetic.invalid" }],
    [
      "missing key",
      (() => {
        const value = intent();
        delete value["handle"];
        return value;
      })(),
    ],
    ["array", []],
    ["null", null],
  ])("rejects an intent with %s", (_label, value) => {
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(value, runtime(), budget()),
    ).toThrow();
  });

  it("rejects accessor-backed and proxied intents without invoking traps", () => {
    let getterCalls = 0;
    const accessor = intent();
    Object.defineProperty(accessor, "operation", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "programs";
      },
    });
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(accessor, runtime(), budget()),
    ).toThrow("HACKERONE_REQUEST_SCHEMA_INVALID");
    expect(getterCalls).toBe(0);

    let proxyTrapCalls = 0;
    const proxy = new Proxy(intent(), {
      get() {
        proxyTrapCalls += 1;
        return undefined;
      },
    });
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(proxy, runtime(), budget()),
    ).toThrow("HACKERONE_REQUEST_SCHEMA_INVALID");
    expect(proxyTrapCalls).toBe(0);
  });
});

describe("HackerOne handle and page validation", () => {
  it.each([
    "a",
    "synthetic",
    "synthetic-program",
    "synthetic_program_2",
    `a${"b".repeat(126)}z`,
  ])("accepts the strong handle %s", (handle) => {
    expect(isStrongHackerOneProgramHandle(handle)).toBe(true);
  });

  it.each([
    "",
    "Synthetic",
    "-synthetic",
    "synthetic-",
    "_synthetic",
    "synthetic_",
    "../synthetic",
    "synthetic/path",
    "synthetic%2fpath",
    "synthetic.path",
    "synthetıc",
    `a${"b".repeat(128)}`,
    null,
    1,
  ])("rejects the weak handle %s", (handle) => {
    expect(isStrongHackerOneProgramHandle(handle)).toBe(false);
  });

  it("binds handles to detail operations and forbids them on list operations", () => {
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(
        { ...intent("programs"), handle: "synthetic-program" },
        runtime(),
        budget(),
      ),
    ).toThrow("HACKERONE_HANDLE_INVALID");
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(
        { ...intent("program"), handle: null },
        runtime(),
        budget(),
      ),
    ).toThrow("HACKERONE_HANDLE_INVALID");
  });

  it.each([
    ["page zero", { number: 0, size: 10 }],
    ["page two", { number: 2, size: 10 }],
    ["size zero", { number: 1, size: 0 }],
    ["size over maximum", { number: 1, size: 101 }],
    ["fractional size", { number: 1, size: 1.5 }],
    ["unknown page key", { number: 1, size: 10, cursor: "synthetic" }],
    ["missing page key", { number: 1 }],
    ["null page", null],
  ])("rejects %s on a paginated operation", (_label, page) => {
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(
        { ...intent("programs"), page },
        runtime(),
        budget(),
      ),
    ).toThrow("HACKERONE_PAGE_INVALID");
  });

  it("forbids a page object on a single-program detail request", () => {
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(
        { ...intent("program"), page: { number: 1, size: 1 } },
        runtime(),
        budget(),
      ),
    ).toThrow("HACKERONE_PAGE_INVALID");
  });
});

describe("HackerOne runtime and request budget gates", () => {
  it("rejects disabled, fabricated, and proxied runtime states", () => {
    const disabled = resolveHackerOneMetadataReadRuntime(undefined);
    const enabled = runtime();
    for (const untrusted of [
      disabled,
      { ...enabled },
      new Proxy(enabled, {}),
      null,
    ])
      expect(() =>
        createInitialHackerOneMetadataRequestPlan(
          intent(),
          untrusted,
          budget(),
        ),
      ).toThrow("HACKERONE_METADATA_CAPABILITY_DISABLED");
  });

  it.each([
    [
      "negative consumed",
      { consumedRequests: -1, activeRequests: 0, requestsInCurrentMinute: 0 },
    ],
    [
      "fractional consumed",
      { consumedRequests: 1.5, activeRequests: 0, requestsInCurrentMinute: 0 },
    ],
    [
      "active over consumed",
      { consumedRequests: 0, activeRequests: 1, requestsInCurrentMinute: 0 },
    ],
    [
      "minute over consumed",
      { consumedRequests: 0, activeRequests: 0, requestsInCurrentMinute: 1 },
    ],
    ["unknown key", { ...budget(), callerAllows: true }],
    ["missing key", { consumedRequests: 0, activeRequests: 0 }],
    ["array", []],
    ["null", null],
  ])("rejects an invalid budget observation: %s", (_label, value) => {
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(intent(), runtime(), value),
    ).toThrow("HACKERONE_REQUEST_BUDGET_INVALID");
  });

  it("blocks exhausted total, concurrency, and rate budgets", () => {
    const configured = runtime(10, 5);
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(
        intent(),
        configured,
        budget({ consumedRequests: 10 }),
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(
        intent(),
        configured,
        budget({ consumedRequests: 1, activeRequests: 1 }),
      ),
    ).toThrow("HACKERONE_REQUEST_CONCURRENCY_EXCEEDED");
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(
        intent(),
        configured,
        budget({ consumedRequests: 5, requestsInCurrentMinute: 5 }),
      ),
    ).toThrow("HACKERONE_REQUEST_RATE_EXCEEDED");
  });

  it("rejects accessor-backed budget observations without invoking accessors", () => {
    let calls = 0;
    const observation = budget() as unknown as Record<string, unknown>;
    Object.defineProperty(observation, "activeRequests", {
      enumerable: true,
      get() {
        calls += 1;
        return 0;
      },
    });
    expect(() =>
      createInitialHackerOneMetadataRequestPlan(
        intent(),
        runtime(),
        observation,
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_INVALID");
    expect(calls).toBe(0);
  });
});

describe("HackerOne pagination continuation", () => {
  function firstPage() {
    return createInitialHackerOneMetadataRequestPlan(
      intent("structured_scopes"),
      runtime(),
      budget(),
    );
  }

  it.each([
    "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    "https://api.hackerone.com:443/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page%5Bnumber%5D=2&page%5Bsize%5D=10",
    "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[size]=10&page[number]=2",
  ])("accepts only the exact next page URL %s", (nextUrl) => {
    const plan = createNextHackerOneMetadataRequestPlan(
      firstPage(),
      nextUrl,
      runtime(),
      budget({ consumedRequests: 1 }),
    );
    expect(plan).toMatchObject({
      operation: "structured_scopes",
      method: "GET",
      path: "/v1/hackers/programs/synthetic-program/structured_scopes",
      query: "?page[number]=2&page[size]=10",
      handle: "synthetic-program",
      page: { number: 2, size: 10 },
      followRedirects: false,
      budgetUnits: 1,
    });
  });

  it("returns null without producing another request when pagination ends", () => {
    expect(
      createNextHackerOneMetadataRequestPlan(
        firstPage(),
        null,
        runtime(),
        budget(),
      ),
    ).toBeNull();
  });

  it.each([
    [
      "relative URL",
      "/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    ],
    [
      "plain HTTP",
      "http://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    ],
    [
      "foreign host",
      "https://synthetic.invalid/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    ],
    [
      "host suffix",
      "https://api.hackerone.com.synthetic.invalid/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    ],
    [
      "userinfo",
      "https://synthetic@api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    ],
    [
      "foreign port",
      "https://api.hackerone.com:444/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    ],
    [
      "changed operation",
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/scope_exclusions?page[number]=2&page[size]=10",
    ],
    [
      "changed handle",
      "https://api.hackerone.com/v1/hackers/programs/other-program/structured_scopes?page[number]=2&page[size]=10",
    ],
    [
      "same page",
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=1&page[size]=10",
    ],
    [
      "skipped page",
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=3&page[size]=10",
    ],
    [
      "changed size",
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=100",
    ],
    [
      "extra query",
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10&extra=1",
    ],
    [
      "fragment",
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10#synthetic",
    ],
    [
      "non-ASCII",
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10&label=synthetıc",
    ],
  ])("blocks a pagination link with %s", (_label, nextUrl) => {
    expect(() =>
      createNextHackerOneMetadataRequestPlan(
        firstPage(),
        nextUrl,
        runtime(),
        budget({ consumedRequests: 1 }),
      ),
    ).toThrow("HACKERONE_PAGINATION_BLOCKED");
  });

  it("blocks oversized and non-string pagination values", () => {
    for (const value of ["x".repeat(4_097), 2, {}, undefined])
      expect(() =>
        createNextHackerOneMetadataRequestPlan(
          firstPage(),
          value,
          runtime(),
          budget({ consumedRequests: 1 }),
        ),
      ).toThrow("HACKERONE_PAGINATION_BLOCKED");
  });

  it("accepts continuations only from genuine plans", () => {
    const genuine = firstPage();
    const next =
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10";
    for (const current of [{ ...genuine }, new Proxy(genuine, {}), null])
      expect(() =>
        createNextHackerOneMetadataRequestPlan(
          current,
          next,
          runtime(),
          budget({ consumedRequests: 1 }),
        ),
      ).toThrow("HACKERONE_PAGINATION_BLOCKED");
  });

  it("rechecks runtime and budget before every continuation", () => {
    const next =
      "https://api.hackerone.com/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10";
    expect(() =>
      createNextHackerOneMetadataRequestPlan(
        firstPage(),
        next,
        resolveHackerOneMetadataReadRuntime(undefined),
        budget({ consumedRequests: 1 }),
      ),
    ).toThrow("HACKERONE_METADATA_CAPABILITY_DISABLED");
    expect(() =>
      createNextHackerOneMetadataRequestPlan(
        firstPage(),
        next,
        runtime(1, 1),
        budget({ consumedRequests: 1, requestsInCurrentMinute: 1 }),
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");
  });

  it("does not allow a detail plan to acquire pagination", () => {
    const detail = createInitialHackerOneMetadataRequestPlan(
      intent("program"),
      runtime(),
      budget(),
    );
    expect(() =>
      createNextHackerOneMetadataRequestPlan(
        detail,
        "https://api.hackerone.com/v1/hackers/programs/synthetic-program?page[number]=2&page[size]=10",
        runtime(),
        budget({ consumedRequests: 1 }),
      ),
    ).toThrow("HACKERONE_PAGINATION_BLOCKED");
  });
});
