import type {
  Browser,
  BrowserContext,
  Route,
  WebSocketRoute,
} from "playwright";
import { describe, expect, it } from "vitest";
import { createGuardedContext } from "../../../packages/egress-guard/playwright.js";
import { programConfig } from "../../fixtures/factories.js";

describe("Playwright context guard", () => {
  it("installs HTTP and WebSocket interception before returning", async () => {
    let httpHandler: ((route: Route) => Promise<void>) | undefined;
    let websocketHandler: ((route: WebSocketRoute) => void) | undefined;
    const context = {
      route(_pattern: string, handler: (route: Route) => Promise<void>) {
        httpHandler = handler;
        return Promise.resolve();
      },
      routeWebSocket(
        _pattern: RegExp,
        handler: (route: WebSocketRoute) => void,
      ) {
        websocketHandler = handler;
        return Promise.resolve();
      },
    } as unknown as BrowserContext;
    const browser = {
      newContext: () => Promise.resolve(context),
    } as unknown as Browser;
    await expect(
      createGuardedContext(browser, { config: programConfig() }),
    ).resolves.toBe(context);
    expect(httpHandler).toBeTypeOf("function");
    expect(websocketHandler).toBeTypeOf("function");

    let aborted = false;
    const route = {
      request: () => ({
        url: () => "https://evil.test/",
        method: () => "GET",
        resourceType: () => "document",
        isNavigationRequest: () => true,
        redirectedFrom: () => null,
      }),
      abort: () => {
        aborted = true;
        return Promise.resolve();
      },
      continue: () => Promise.resolve(),
    } as unknown as Route;
    await httpHandler?.(route);
    expect(aborted).toBe(true);

    let closeReason = "";
    websocketHandler?.({
      close: (options: Parameters<WebSocketRoute["close"]>[0]) => {
        closeReason = options?.reason ?? "";
      },
    } as unknown as WebSocketRoute);
    expect(closeReason).toBe("BLOCK_WEBSOCKET");
  });

  it("allows exact targets and derives supporting capture modes", async () => {
    let handler: ((route: Route) => Promise<void>) | undefined;
    const context = {
      route: (_pattern: string, value: (route: Route) => Promise<void>) => {
        handler = value;
        return Promise.resolve();
      },
      routeWebSocket: () => Promise.resolve(),
    } as unknown as BrowserContext;
    const browser = {
      newContext: () => Promise.resolve(context),
    } as unknown as Browser;
    await createGuardedContext(browser, { config: programConfig() });
    for (const url of [
      "https://api.example.test/api/",
      "https://cdn.example.test/",
    ]) {
      let continued = false;
      await handler?.({
        request: () => ({
          url: () => url,
          method: () => "GET",
          resourceType: () => "fetch",
          isNavigationRequest: () => false,
          redirectedFrom: () => null,
        }),
        continue: () => {
          continued = true;
          return Promise.resolve();
        },
        abort: () => Promise.resolve(),
      } as unknown as Route);
      expect(continued).toBe(true);
    }
  });
});
