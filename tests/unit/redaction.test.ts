import { randomBytes } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  Pseudonymizer,
  processBody,
  redactHeaders,
  redactJson,
} from "../../packages/redaction/redactor.js";

describe("redaction", () => {
  const pseudonymizer = new Pseudonymizer(randomBytes(32));
  it("drops secret headers and recursively redacts JSON", () => {
    expect(
      redactHeaders({
        Authorization: "hidden",
        Cookie: "hidden",
        Accept: "application/json",
      }),
    ).toEqual({ accept: "application/json" });
    expect(
      redactJson(
        { nested: { password: "hidden" }, email: "person@example.test" },
        pseudonymizer,
      ),
    ).toEqual({ nested: { password: "[REDACTED]" }, email: "[REDACTED]" });
  });
  it("hashes oversized and binary bodies without text", () => {
    const large = processBody(
      Buffer.alloc(20),
      { "content-type": "text/plain" },
      { maxBytes: 10, allowedContentTypes: ["text/plain"], pseudonymizer },
    );
    expect(large).toMatchObject({
      disposition: "metadata_only",
      reason: "BODY_TOO_LARGE",
    });
    expect(large).not.toHaveProperty("text");
    const binary = processBody(
      Uint8Array.from([0xff, 0xfe]),
      { "content-type": "text/plain" },
      { maxBytes: 10, allowedContentTypes: ["text/plain"], pseudonymizer },
    );
    expect(binary.reason).toBe("BODY_BINARY");
  });
  it("quarantines unknown identity structures", () => {
    const body = processBody(
      Buffer.from(JSON.stringify({ passport: "unknown" })),
      { "content-type": "application/json" },
      {
        maxBytes: 100,
        allowedContentTypes: ["application/json"],
        pseudonymizer,
      },
    );
    expect(body.disposition).toBe("quarantine");
    expect(body).not.toHaveProperty("json");
  });
  it("creates stable key-bound HMAC pseudonyms", () => {
    const key = randomBytes(32);
    const first = new Pseudonymizer(key);
    const second = new Pseudonymizer(randomBytes(32));
    expect(first.pseudonym("a@example.test")).toBe(
      first.pseudonym("a@example.test"),
    );
    expect(first.pseudonym("a@example.test")).not.toBe(
      second.pseudonym("a@example.test"),
    );
    expect(first.pseudonym("a@example.test")).not.toContain("a@example.test");
  });
});

it("header redaction never retains arbitrary sensitive headers", () => {
  fc.assert(
    fc.property(fc.string({ minLength: 1, maxLength: 64 }), (value) => {
      expect(
        redactHeaders({
          authorization: value,
          cookie: value,
          "x-api-key": value,
        }),
      ).toEqual({});
    }),
  );
});

it("recursive JSON redaction removes generated secret values", () => {
  fc.assert(
    fc.property(
      fc
        .uint8Array({ minLength: 16, maxLength: 32 })
        .map((bytes) => Buffer.from(bytes).toString("hex")),
      (secret) => {
        const output = JSON.stringify(
          redactJson(
            { nested: [{ token: secret }, { password: secret }] },
            new Pseudonymizer(randomBytes(32)),
          ),
        );
        expect(output).not.toContain(secret);
      },
    ),
  );
});
