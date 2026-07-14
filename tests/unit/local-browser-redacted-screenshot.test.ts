import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  buildOpaqueScreenshotOverlay,
  digestRedactedScreenshot,
  JOURNEY_ROLES,
  JOURNEY_STATES,
  MAX_REDACTED_SCREENSHOT_BYTES,
  REDACTED_SCREENSHOT_HEIGHT,
  REDACTED_SCREENSHOT_WIDTH,
} from "../browser/support/redacted-screenshot.js";

const PNG_SIGNATURE = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
]);
const CRC32_POLYNOMIAL = 0xedb88320;

describe("redacted local-browser screenshot digest", () => {
  it("returns only a digest for a strict 1280x720 PNG and destroys the input", () => {
    const png = makePng();
    const expectedLength = png.byteLength;
    const expectedHash = createHash("sha256").update(png).digest("hex");

    expect(digestRedactedScreenshot(png)).toEqual({
      sha256: expectedHash,
      byteLength: expectedLength,
    });
    expect(isZeroed(png)).toBe(true);
  });

  it("rejects a mutated chunk CRC and destroys the input", () => {
    const png = makePng();
    const idatDataOffset = findChunkDataOffset(png, "IDAT");
    png[idatDataOffset] = (png[idatDataOffset] ?? 0) ^ 0xff;

    expect(() => digestRedactedScreenshot(png)).toThrow(
      "REDACTED_SCREENSHOT_CRC_INVALID",
    );
    expect(isZeroed(png)).toBe(true);
  });

  it("rejects an invalid PNG signature and destroys the input", () => {
    const png = makePng();
    png[0] = 0;

    expect(() => digestRedactedScreenshot(png)).toThrow(
      "REDACTED_SCREENSHOT_SIGNATURE_INVALID",
    );
    expect(isZeroed(png)).toBe(true);
  });

  it.each(["tEXt", "zTXt", "iTXt", "eXIf"])(
    "blocks %s metadata and destroys the input",
    (type) => {
      const png = makePng({ beforeImageData: [makeChunk(type, [1, 2, 3])] });

      expect(() => digestRedactedScreenshot(png)).toThrow(
        "REDACTED_SCREENSHOT_METADATA_BLOCKED",
      );
      expect(isZeroed(png)).toBe(true);
    },
  );

  it("blocks every non-allowlisted chunk", () => {
    const png = makePng({ beforeImageData: [makeChunk("pHYs", [0, 0, 0])] });

    expect(() => digestRedactedScreenshot(png)).toThrow(
      "REDACTED_SCREENSHOT_CHUNK_BLOCKED",
    );
    expect(isZeroed(png)).toBe(true);
  });

  it("rejects wrong dimensions with a valid IHDR CRC", () => {
    const png = makePng({ width: 1_279 });

    expect(() => digestRedactedScreenshot(png)).toThrow(
      "REDACTED_SCREENSHOT_DIMENSIONS_INVALID",
    );
    expect(isZeroed(png)).toBe(true);
  });

  it("rejects unsupported IHDR pixel formats with a valid CRC", () => {
    const png = makePng({ bitDepth: 16 });

    expect(() => digestRedactedScreenshot(png)).toThrow(
      "REDACTED_SCREENSHOT_IHDR_INVALID",
    );
    expect(isZeroed(png)).toBe(true);
  });

  it("rejects oversized input before parsing and destroys it", () => {
    const png = Buffer.alloc(MAX_REDACTED_SCREENSHOT_BYTES + 1, 0xa5);

    expect(() => digestRedactedScreenshot(png)).toThrow(
      "REDACTED_SCREENSHOT_SIZE_INVALID",
    );
    expect(isZeroed(png)).toBe(true);
  });

  it("rejects truncated chunks, missing IEND and trailing bytes", () => {
    const truncated = makePng().subarray(0, -2);
    expect(() => digestRedactedScreenshot(truncated)).toThrow(
      "REDACTED_SCREENSHOT_CHUNK_TRUNCATED",
    );
    expect(isZeroed(truncated)).toBe(true);

    const withoutEnd = makePng({ omitEnd: true });
    expect(() => digestRedactedScreenshot(withoutEnd)).toThrow(
      "REDACTED_SCREENSHOT_IEND_MISSING",
    );
    expect(isZeroed(withoutEnd)).toBe(true);

    const trailing = Buffer.concat([makePng(), Buffer.from([0])]);
    expect(() => digestRedactedScreenshot(trailing)).toThrow(
      "REDACTED_SCREENSHOT_TRAILING_DATA",
    );
    expect(isZeroed(trailing)).toBe(true);
  });
});

describe("fixed opaque local-browser overlay", () => {
  it("builds only closed role/state labels and fully opaque static markup", () => {
    const overlay = buildOpaqueScreenshotOverlay("Owner", "invitations");

    expect(JOURNEY_ROLES).toEqual(["Owner", "Member", "External"]);
    expect(JOURNEY_STATES).toEqual([
      "service",
      "organization",
      "projects",
      "documents",
      "invitations",
      "test_objects",
      "policy",
      "state",
    ]);
    expect(overlay).toMatchObject({
      role: "Owner",
      state: "invitations",
      label: "Owner · Invitations · LOCAL REDACTED EVIDENCE",
      maskColor: "#142024",
    });
    expect(overlay.html).toBe(
      '<section data-local-redaction-overlay="true" role="img" aria-label="Owner · Invitations · LOCAL REDACTED EVIDENCE"><span>Owner · Invitations · LOCAL REDACTED EVIDENCE</span></section>',
    );
    expect(overlay.css).toContain("inset: 0 !important");
    expect(overlay.css).toContain("opacity: 1 !important");
    expect(overlay.css).toContain("background: rgb(16 24 32) !important");
    expect(Object.isFrozen(overlay)).toBe(true);
  });

  it.each([
    ["Member", "invitations"],
    ["External", "invitations"],
    ["External", "documents"],
    ["External", "test_objects"],
  ])("blocks the invalid role/state pair %s/%s", (role, state) => {
    expect(() => buildOpaqueScreenshotOverlay(role, state)).toThrow(
      "REDACTED_SCREENSHOT_ROLE_STATE_BLOCKED",
    );
  });

  it("rejects untrusted role and state strings without reflecting them", () => {
    expect(() =>
      buildOpaqueScreenshotOverlay('<img src=x onerror="alert(1)">', "service"),
    ).toThrow("REDACTED_SCREENSHOT_ROLE_INVALID");
    expect(() => buildOpaqueScreenshotOverlay("Owner", "../../secret")).toThrow(
      "REDACTED_SCREENSHOT_STATE_INVALID",
    );
  });
});

function makePng(
  options: {
    readonly width?: number;
    readonly height?: number;
    readonly bitDepth?: number;
    readonly beforeImageData?: readonly Buffer[];
    readonly omitEnd?: boolean;
  } = {},
): Buffer {
  const width = options.width ?? REDACTED_SCREENSHOT_WIDTH;
  const height = options.height ?? REDACTED_SCREENSHOT_HEIGHT;
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = options.bitDepth ?? 8;
  header[9] = 6;
  header[10] = 0;
  header[11] = 0;
  header[12] = 0;

  const raw = Buffer.alloc((width * 4 + 1) * height);
  try {
    const imageData = deflateSync(raw);
    return Buffer.concat([
      PNG_SIGNATURE,
      makeChunk("IHDR", header),
      ...(options.beforeImageData ?? []),
      makeChunk("IDAT", imageData),
      ...(options.omitEnd === true ? [] : [makeChunk("IEND", [])]),
    ]);
  } finally {
    raw.fill(0);
  }
}

function makeChunk(type: string, data: Uint8Array | readonly number[]): Buffer {
  const typeBytes = Buffer.from(type, "ascii");
  const dataBytes = Buffer.from(data);
  const result = Buffer.alloc(12 + dataBytes.byteLength);
  result.writeUInt32BE(dataBytes.byteLength, 0);
  typeBytes.copy(result, 4);
  dataBytes.copy(result, 8);
  result.writeUInt32BE(
    crc32(result, 4, 8 + dataBytes.byteLength),
    8 + dataBytes.byteLength,
  );
  return result;
}

function findChunkDataOffset(png: Buffer, expectedType: string): number {
  let offset = PNG_SIGNATURE.byteLength;
  while (offset < png.byteLength) {
    const length = png.readUInt32BE(offset);
    const type = png.toString("ascii", offset + 4, offset + 8);
    if (type === expectedType) return offset + 8;
    offset += 12 + length;
  }
  throw new Error("TEST_CHUNK_MISSING");
}

function crc32(bytes: Uint8Array, start: number, end: number): number {
  let crc = 0xffffffff;
  for (let offset = start; offset < end; offset += 1) {
    crc ^= bytes[offset] ?? 0;
    for (let bit = 0; bit < 8; bit += 1)
      crc = (crc >>> 1) ^ ((crc & 1) === 1 ? CRC32_POLYNOMIAL : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function isZeroed(bytes: Uint8Array): boolean {
  return bytes.every((value) => value === 0);
}
