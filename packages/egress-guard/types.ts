import type { ProgramConfig } from "../config/types.js";

export type CaptureMode = "metadata_only" | "none" | "redacted";
export type ResourceKind =
  | "document"
  | "fetch"
  | "form"
  | "frame"
  | "navigation"
  | "other"
  | "popup"
  | "xhr";

export interface EgressRequest {
  readonly url: string;
  readonly method: string;
  readonly captureMode: CaptureMode;
  readonly resourceKind: ResourceKind;
  readonly isRedirect: boolean;
}

export type EgressReasonCode =
  | "ALLOW_SUPPORTING_HOST"
  | "ALLOW_TARGET"
  | "BLOCK_BAD_URL"
  | "BLOCK_CAPTURE_MODE"
  | "BLOCK_HOST"
  | "BLOCK_HTTP"
  | "BLOCK_METHOD"
  | "BLOCK_PATH"
  | "BLOCK_PORT"
  | "BLOCK_REDIRECT"
  | "BLOCK_SCHEME"
  | "BLOCK_USERINFO";

export interface EgressDecision {
  readonly allow: boolean;
  readonly reason: EgressReasonCode;
  readonly assetKind: "none" | "supporting" | "target";
  readonly normalized?: {
    readonly scheme: string;
    readonly host: string;
    readonly port: number;
    readonly path: string;
    readonly method: string;
  };
}

export interface EgressPolicy {
  readonly config: ProgramConfig;
  readonly localTestMode?: boolean;
}
