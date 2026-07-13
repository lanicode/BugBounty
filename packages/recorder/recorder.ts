import type { EncryptedEventStore } from "../event-store/store.js";
import {
  processBody,
  redactHeaders,
  redactUrl,
  type Pseudonymizer,
  type RedactedBody,
} from "../redaction/redactor.js";
import type { JsonValue } from "../shared/canonical.js";

export interface CapturedExchange {
  readonly id: string;
  readonly timestamp: string;
  readonly assetKind: "supporting" | "target";
  readonly request: {
    readonly url: string;
    readonly method: string;
    readonly headers: Readonly<Record<string, string>>;
    readonly body?: Uint8Array;
  };
  readonly response: {
    readonly status: number;
    readonly headers: Readonly<Record<string, string>>;
    readonly body?: Uint8Array;
  };
}

export class SelectiveEventRecorder {
  public constructor(
    private readonly normalStore: EncryptedEventStore,
    private readonly quarantineStore: EncryptedEventStore,
    private readonly options: {
      readonly maxBytes: number;
      readonly allowedContentTypes: readonly string[];
      readonly pseudonymizer: Pseudonymizer;
    },
  ) {}

  public async record(
    exchange: CapturedExchange,
  ): Promise<{ store: "normal" | "quarantine"; path: string }> {
    const requestBody =
      exchange.request.body === undefined
        ? undefined
        : processBody(
            exchange.request.body,
            exchange.request.headers,
            this.options,
          );
    const responseBody =
      exchange.response.body === undefined
        ? undefined
        : processBody(
            exchange.response.body,
            exchange.response.headers,
            this.options,
          );
    const quarantined =
      requestBody?.disposition === "quarantine" ||
      responseBody?.disposition === "quarantine";
    const event = {
      version: 1,
      timestamp: exchange.timestamp,
      assetKind: exchange.assetKind,
      findingEligible: exchange.assetKind === "target",
      request: {
        url: redactUrl(exchange.request.url),
        method: exchange.request.method.toUpperCase(),
        headers: redactHeaders(exchange.request.headers),
        ...(requestBody === undefined ? {} : { body: safeBody(requestBody) }),
      },
      response: {
        status: exchange.response.status,
        headers: redactHeaders(exchange.response.headers),
        ...(responseBody === undefined ? {} : { body: safeBody(responseBody) }),
      },
    } satisfies JsonValue;
    const store = quarantined ? this.quarantineStore : this.normalStore;
    return {
      store: quarantined ? "quarantine" : "normal",
      path: await store.write(exchange.id, event),
    };
  }
}

function safeBody(body: RedactedBody): JsonValue {
  return {
    disposition: body.disposition,
    byteLength: body.byteLength,
    sha256: body.sha256,
    ...(body.contentType === undefined
      ? {}
      : { contentType: body.contentType }),
    ...(body.reason === undefined ? {} : { reason: body.reason }),
    ...(body.text === undefined ? {} : { text: body.text }),
    ...(body.json === undefined ? {} : { json: body.json }),
  };
}
