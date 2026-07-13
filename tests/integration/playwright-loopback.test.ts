import { once } from "node:events";
import { createServer } from "node:http";
import { chromium } from "playwright";
import { afterEach, expect, it } from "vitest";
import { createGuardedContext } from "../../packages/egress-guard/playwright.js";
import { programConfig } from "../fixtures/factories.js";

const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(async (server) => {
      server.close();
      await once(server, "close");
    }),
  );
});

async function browserServer(): Promise<{
  origin: string;
  hits: Map<string, number>;
  upgrades: () => number;
}> {
  const hits = new Map<string, number>();
  let upgrades = 0;
  const server = createServer((request, response) => {
    const path = request.url?.split("?", 1)[0] ?? "/";
    hits.set(path, (hits.get(path) ?? 0) + 1);
    if (path === "/api/redirect") {
      response.writeHead(302, { location: "/api/redirected" });
      response.end();
      return;
    }
    if (path === "/api/start") {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(
        "<!doctype html><title>local guard fixture</title><body>local</body>",
      );
      return;
    }
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("local");
  });
  server.on("upgrade", (_request, socket) => {
    upgrades += 1;
    socket.destroy();
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("LOCAL_SERVER_ADDRESS");
  return {
    origin: `http://127.0.0.1:${address.port}`,
    hits,
    upgrades: () => upgrades,
  };
}

it("guards real popup, iframe, fetch, form, redirect, service worker and WebSocket channels", async () => {
  const allowed = await browserServer();
  const blocked = await browserServer();
  const port = Number(new URL(allowed.origin).port);
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await createGuardedContext(browser, {
      config: programConfig({ host: "127.0.0.1", port, allowHttp: true }),
      localTestMode: true,
    });
    const page = await context.newPage();
    await page.goto(`${allowed.origin}/api/start`);

    await expect(
      page.evaluate(() => fetch("/api/fetch").then((response) => response.ok)),
    ).resolves.toBe(true);
    await page.setContent(
      `<iframe src="${allowed.origin}/api/frame"></iframe>`,
    );
    await page.locator("iframe").contentFrame().locator("body").waitFor();

    const popupPromise = context.waitForEvent("page");
    await page.evaluate(
      (url) => window.open(url),
      `${allowed.origin}/api/popup`,
    );
    const popup = await popupPromise;
    await popup.waitForLoadState();

    const formPagePromise = context.waitForEvent("page");
    await page.setContent(
      `<form action="${allowed.origin}/api/form" method="GET" target="form-result"><button>submit</button></form>`,
    );
    await page.locator("button").click();
    const formPage = await formPagePromise;
    await formPage.waitForLoadState();

    await expect(
      page.evaluate(
        (url) =>
          fetch(url)
            .then(() => true)
            .catch(() => false),
        `${blocked.origin}/api/blocked`,
      ),
    ).resolves.toBe(false);
    await page.evaluate(() => fetch("/api/redirect").catch(() => undefined));
    await expect(
      page.evaluate(() =>
        navigator.serviceWorker
          .register("/api/sw.js")
          .then(() => true)
          .catch(() => false),
      ),
    ).resolves.toBe(false);
    await page.evaluate(
      (url) =>
        new Promise<void>((resolve) => {
          const websocket = new WebSocket(url);
          websocket.addEventListener(
            "close",
            () => {
              resolve();
            },
            { once: true },
          );
          websocket.addEventListener(
            "error",
            () => {
              resolve();
            },
            { once: true },
          );
        }),
      `ws://127.0.0.1:${port}/api/socket`,
    );

    expect(allowed.hits.get("/api/fetch")).toBe(1);
    expect(allowed.hits.get("/api/frame")).toBe(1);
    expect(allowed.hits.get("/api/popup")).toBe(1);
    expect(allowed.hits.get("/api/form")).toBe(1);
    expect(allowed.hits.get("/api/redirect")).toBe(1);
    expect(allowed.hits.get("/api/redirected") ?? 0).toBe(0);
    expect(allowed.hits.get("/api/sw.js") ?? 0).toBe(0);
    expect(allowed.upgrades()).toBe(0);
    expect(blocked.hits.get("/api/blocked") ?? 0).toBe(0);
    await context.close();
  } finally {
    await browser.close();
  }
});
