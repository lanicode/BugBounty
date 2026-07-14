import { createHash } from "node:crypto";

export const REDACTED_SCREENSHOT_WIDTH = 1_280;
export const REDACTED_SCREENSHOT_HEIGHT = 720;
export const MAX_REDACTED_SCREENSHOT_BYTES = 1_024 * 1_024;

export const JOURNEY_ROLES = Object.freeze([
  "Owner",
  "Member",
  "External",
] as const);
export type JourneyRole = (typeof JOURNEY_ROLES)[number];

export const JOURNEY_STATES = Object.freeze([
  "service",
  "organization",
  "projects",
  "documents",
  "invitations",
  "test_objects",
  "policy",
  "state",
] as const);
export type JourneyState = (typeof JOURNEY_STATES)[number];

export interface RedactedScreenshotDigest {
  readonly sha256: string;
  readonly byteLength: number;
}

export interface OpaqueScreenshotOverlay {
  readonly role: JourneyRole;
  readonly state: JourneyState;
  readonly label: string;
  readonly maskColor: string;
  readonly html: string;
  readonly css: string;
}

const PNG_SIGNATURE = Uint8Array.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
]);
const IHDR_BYTES = 13;
const PNG_CHUNK_OVERHEAD = 12;
const MINIMUM_PNG_BYTES =
  PNG_SIGNATURE.byteLength +
  PNG_CHUNK_OVERHEAD +
  IHDR_BYTES +
  PNG_CHUNK_OVERHEAD +
  1 +
  PNG_CHUNK_OVERHEAD;
const CRC32_POLYNOMIAL = 0xedb88320;

const STATE_LABELS: Readonly<Record<JourneyState, string>> = Object.freeze({
  service: "Service",
  organization: "Organization",
  projects: "Projects",
  documents: "Documents",
  invitations: "Invitations",
  test_objects: "Test objects",
  policy: "Policy",
  state: "State",
});

const OPAQUE_OVERLAY_CSS = String.raw`
[data-local-redaction-overlay="true"] {
  all: initial !important;
  position: fixed !important;
  inset: 0 !important;
  z-index: 2147483647 !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  box-sizing: border-box !important;
  width: 100vw !important;
  height: 100vh !important;
  margin: 0 !important;
  padding: 0 !important;
  overflow: hidden !important;
  opacity: 1 !important;
  background: rgb(16 24 32) !important;
  color: rgb(255 255 255) !important;
  mix-blend-mode: normal !important;
  filter: none !important;
  backdrop-filter: none !important;
  pointer-events: none !important;
  contain: strict !important;
}

[data-local-redaction-overlay="true"] > span {
  all: initial !important;
  display: block !important;
  padding: 16px 24px !important;
  opacity: 1 !important;
  background: rgb(16 24 32) !important;
  color: rgb(255 255 255) !important;
  font: 700 20px/1.4 monospace !important;
  letter-spacing: 0.04em !important;
  text-align: center !important;
  white-space: nowrap !important;
}
`.trim();

/**
 * Releases only a digest of an already-redacted, tightly constrained PNG.
 * The supplied buffer is destroyed on every success and failure path.
 */
export function digestRedactedScreenshot(
  png: Buffer,
): RedactedScreenshotDigest {
  try {
    assertPrivateBuffer(png);
    validatePng(png);
    return Object.freeze({
      sha256: createHash("sha256").update(png).digest("hex"),
      byteLength: png.byteLength,
    });
  } finally {
    destroyBuffer(png);
  }
}

/**
 * Produces only a fixed, fully opaque overlay. Role and state select from
 * closed enums; no caller-provided text, markup, path or encoded image enters
 * the returned DOM fragment.
 */
export function buildOpaqueScreenshotOverlay(
  role: unknown,
  state: unknown,
): OpaqueScreenshotOverlay {
  assertJourneyRole(role);
  assertJourneyState(state);
  assertRoleMayVisitState(role, state);

  const label = `${role} · ${STATE_LABELS[state]} · LOCAL REDACTED EVIDENCE`;
  const maskColor = stateBoundMaskColor(role, state);
  return Object.freeze({
    role,
    state,
    label,
    maskColor,
    html: `<section data-local-redaction-overlay="true" role="img" aria-label="${label}"><span>${label}</span></section>`,
    css: OPAQUE_OVERLAY_CSS,
  });
}

function stateBoundMaskColor(role: JourneyRole, state: JourneyState): string {
  const roleIndex = JOURNEY_ROLES.indexOf(role);
  const stateIndex = JOURNEY_STATES.indexOf(state);
  const red = 16 + roleIndex * 16 + stateIndex;
  const green = 24 + stateIndex * 2;
  const blue = 32 + roleIndex * 8 + stateIndex;
  return `#${hexByte(red)}${hexByte(green)}${hexByte(blue)}`;
}

function hexByte(value: number): string {
  return value.toString(16).padStart(2, "0");
}

function assertPrivateBuffer(value: unknown): asserts value is Buffer {
  if (
    !Buffer.isBuffer(value) ||
    Object.getPrototypeOf(value) !== Buffer.prototype ||
    (typeof SharedArrayBuffer !== "undefined" &&
      value.buffer instanceof SharedArrayBuffer)
  )
    throw new Error("REDACTED_SCREENSHOT_BUFFER_INVALID");
}

function destroyBuffer(value: unknown): void {
  if (!Buffer.isBuffer(value)) return;
  Uint8Array.prototype.fill.call(value, 0);
}

function validatePng(png: Buffer): void {
  if (
    png.byteLength < MINIMUM_PNG_BYTES ||
    png.byteLength > MAX_REDACTED_SCREENSHOT_BYTES
  )
    throw new Error("REDACTED_SCREENSHOT_SIZE_INVALID");

  for (let index = 0; index < PNG_SIGNATURE.byteLength; index += 1)
    if (png[index] !== PNG_SIGNATURE[index])
      throw new Error("REDACTED_SCREENSHOT_SIGNATURE_INVALID");

  let offset = PNG_SIGNATURE.byteLength;
  let chunkIndex = 0;
  let sawHeader = false;
  let sawImageData = false;
  let imageDataBytes = 0;

  while (offset < png.byteLength) {
    if (png.byteLength - offset < PNG_CHUNK_OVERHEAD)
      throw new Error("REDACTED_SCREENSHOT_CHUNK_TRUNCATED");

    const dataLength = readUint32(png, offset);
    const typeOffset = offset + 4;
    const dataOffset = typeOffset + 4;
    if (dataLength > png.byteLength - dataOffset - 4)
      throw new Error("REDACTED_SCREENSHOT_CHUNK_TRUNCATED");
    const dataEnd = dataOffset + dataLength;
    const chunkEnd = dataEnd + 4;
    const type = readChunkType(png, typeOffset);
    const storedCrc = readUint32(png, dataEnd);
    const computedCrc = crc32(png, typeOffset, dataEnd);
    if (storedCrc !== computedCrc)
      throw new Error("REDACTED_SCREENSHOT_CRC_INVALID");

    switch (type) {
      case "IHDR":
        if (chunkIndex !== 0 || sawHeader || sawImageData)
          throw new Error("REDACTED_SCREENSHOT_CHUNK_ORDER_INVALID");
        validateHeader(png, dataOffset, dataLength);
        sawHeader = true;
        break;
      case "IDAT":
        if (!sawHeader)
          throw new Error("REDACTED_SCREENSHOT_CHUNK_ORDER_INVALID");
        sawImageData = true;
        imageDataBytes += dataLength;
        break;
      case "IEND":
        if (
          !sawHeader ||
          !sawImageData ||
          imageDataBytes === 0 ||
          dataLength !== 0
        )
          throw new Error("REDACTED_SCREENSHOT_CHUNK_ORDER_INVALID");
        if (chunkEnd !== png.byteLength)
          throw new Error("REDACTED_SCREENSHOT_TRAILING_DATA");
        return;
      case "tEXt":
      case "zTXt":
      case "iTXt":
      case "eXIf":
        throw new Error("REDACTED_SCREENSHOT_METADATA_BLOCKED");
      default:
        throw new Error("REDACTED_SCREENSHOT_CHUNK_BLOCKED");
    }

    offset = chunkEnd;
    chunkIndex += 1;
  }

  throw new Error("REDACTED_SCREENSHOT_IEND_MISSING");
}

function validateHeader(
  png: Buffer,
  dataOffset: number,
  dataLength: number,
): void {
  if (dataLength !== IHDR_BYTES)
    throw new Error("REDACTED_SCREENSHOT_IHDR_INVALID");
  const width = readUint32(png, dataOffset);
  const height = readUint32(png, dataOffset + 4);
  if (
    width !== REDACTED_SCREENSHOT_WIDTH ||
    height !== REDACTED_SCREENSHOT_HEIGHT
  )
    throw new Error("REDACTED_SCREENSHOT_DIMENSIONS_INVALID");

  const bitDepth = png[dataOffset + 8];
  const colorType = png[dataOffset + 9];
  const compression = png[dataOffset + 10];
  const filter = png[dataOffset + 11];
  const interlace = png[dataOffset + 12];
  if (
    bitDepth !== 8 ||
    (colorType !== 2 && colorType !== 6) ||
    compression !== 0 ||
    filter !== 0 ||
    interlace !== 0
  )
    throw new Error("REDACTED_SCREENSHOT_IHDR_INVALID");
}

function readChunkType(bytes: Buffer, offset: number): string {
  let type = "";
  for (let index = 0; index < 4; index += 1) {
    const value = bytes[offset + index];
    if (
      value === undefined ||
      !((value >= 0x41 && value <= 0x5a) || (value >= 0x61 && value <= 0x7a))
    )
      throw new Error("REDACTED_SCREENSHOT_CHUNK_TYPE_INVALID");
    type += String.fromCharCode(value);
  }
  return type;
}

function readUint32(bytes: Buffer, offset: number): number {
  const first = bytes[offset];
  const second = bytes[offset + 1];
  const third = bytes[offset + 2];
  const fourth = bytes[offset + 3];
  if (
    first === undefined ||
    second === undefined ||
    third === undefined ||
    fourth === undefined
  )
    throw new Error("REDACTED_SCREENSHOT_CHUNK_TRUNCATED");
  return (first * 0x1000000 + second * 0x10000 + third * 0x100 + fourth) >>> 0;
}

function crc32(bytes: Buffer, start: number, end: number): number {
  let crc = 0xffffffff;
  for (let offset = start; offset < end; offset += 1) {
    const value = bytes[offset];
    if (value === undefined)
      throw new Error("REDACTED_SCREENSHOT_CHUNK_TRUNCATED");
    crc ^= value;
    for (let bit = 0; bit < 8; bit += 1)
      crc = (crc >>> 1) ^ ((crc & 1) === 1 ? CRC32_POLYNOMIAL : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function assertJourneyRole(value: unknown): asserts value is JourneyRole {
  if (value !== "Owner" && value !== "Member" && value !== "External")
    throw new Error("REDACTED_SCREENSHOT_ROLE_INVALID");
}

function assertJourneyState(value: unknown): asserts value is JourneyState {
  switch (value) {
    case "service":
    case "organization":
    case "projects":
    case "documents":
    case "invitations":
    case "test_objects":
    case "policy":
    case "state":
      return;
    default:
      throw new Error("REDACTED_SCREENSHOT_STATE_INVALID");
  }
}

function assertRoleMayVisitState(role: JourneyRole, state: JourneyState): void {
  if (state === "invitations" && role !== "Owner")
    throw new Error("REDACTED_SCREENSHOT_ROLE_STATE_BLOCKED");
  if (
    (state === "documents" || state === "test_objects") &&
    role === "External"
  )
    throw new Error("REDACTED_SCREENSHOT_ROLE_STATE_BLOCKED");
}
