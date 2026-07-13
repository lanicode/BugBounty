import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, resolve, sep } from "node:path";
import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import snapshotSchema from "./snapshot.schema.json" with { type: "json" };
import type {
  ProgramSource,
  ProgramSourceSnapshot,
  ValidatedProgramSnapshot,
} from "./types.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import { parseDocument } from "yaml";

const MAX_FIXTURE_BYTES = 1_048_576;
const SENSITIVE_KEY =
  /(?:password|passwd|token|api[_-]?key|authorization|cookie|credential|private[_-]?key)/i;
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateSnapshot = ajv.compile<ProgramSourceSnapshot>(snapshotSchema);

function safeErrors(errors: ErrorObject[] | null | undefined): string {
  return (errors ?? [])
    .map(
      (error) =>
        `PLATFORM_SOURCE_SCHEMA:${error.instancePath || "/"}:${error.keyword}`,
    )
    .join("|");
}

function containsForbiddenSecretKey(value: unknown): boolean {
  const pending: { readonly value: unknown; readonly depth: number }[] = [
    { value, depth: 0 },
  ];
  let visited = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    visited += 1;
    if (current.depth > 64 || visited > 10_000)
      throw new SecurityError("PLATFORM_SOURCE_STRUCTURE_LIMIT");
    if (Array.isArray(current.value)) {
      for (const child of current.value)
        pending.push({ value: child, depth: current.depth + 1 });
    } else if (current.value !== null && typeof current.value === "object") {
      for (const [key, child] of Object.entries(current.value)) {
        if (SENSITIVE_KEY.test(key)) return true;
        pending.push({ value: child, depth: current.depth + 1 });
      }
    }
  }
  return false;
}

export function validateProgramSnapshot(
  value: unknown,
): ValidatedProgramSnapshot {
  if (containsForbiddenSecretKey(value))
    throw new SecurityError("PLATFORM_SOURCE_SECRET_FIELD");
  if (!validateSnapshot(value))
    throw new SecurityError(safeErrors(validateSnapshot.errors));
  const snapshot = freezeSnapshot(value);
  const canonical = canonicalJson(snapshot);
  return { snapshot, canonical, snapshotHash: sha256(canonical) };
}

export class FixtureProgramSource implements ProgramSource {
  public constructor(private readonly fixtureRoot: string) {}

  public async read(reference: string): Promise<ValidatedProgramSnapshot> {
    if (
      reference.length === 0 ||
      isAbsolute(reference) ||
      reference.includes("\\") ||
      reference.split("/").includes("..") ||
      !reference.endsWith(".json")
    )
      throw new SecurityError("PLATFORM_SOURCE_REFERENCE_INVALID");
    const root = await realpath(this.fixtureRoot).catch(() => {
      throw new SecurityError("PLATFORM_SOURCE_ROOT_INVALID");
    });
    const candidate = resolve(root, reference);
    const candidateReal = await realpath(candidate).catch(() => {
      throw new SecurityError("PLATFORM_SOURCE_NOT_FOUND");
    });
    if (!candidateReal.startsWith(`${root}${sep}`))
      throw new SecurityError("PLATFORM_SOURCE_PATH_ESCAPE");
    if (
      candidateReal !== candidate ||
      (await lstat(candidate)).isSymbolicLink()
    )
      throw new SecurityError("PLATFORM_SOURCE_SYMLINK_BLOCKED");
    let handle: Awaited<ReturnType<typeof open>>;
    try {
      handle = await open(candidate, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch {
      throw new SecurityError("PLATFORM_SOURCE_OPEN_FAILED");
    }
    let value: unknown;
    try {
      const metadata = await handle.stat();
      if (!metadata.isFile() || metadata.size > MAX_FIXTURE_BYTES)
        throw new SecurityError("PLATFORM_SOURCE_SIZE_INVALID");
      const bytes = await handle.readFile();
      const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const duplicateCheck = parseDocument(source, {
        uniqueKeys: true,
        merge: false,
        version: "1.2",
      });
      if (duplicateCheck.errors.length > 0)
        throw new SecurityError("PLATFORM_SOURCE_JSON_AMBIGUOUS");
      value = JSON.parse(source) as unknown;
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("PLATFORM_SOURCE_JSON_INVALID");
    } finally {
      await handle.close();
    }
    return validateProgramSnapshot(value);
  }
}

function freezeSnapshot(value: ProgramSourceSnapshot): ProgramSourceSnapshot {
  const targets = Object.freeze(
    value.network.targets.map((target) =>
      Object.freeze({
        scheme: target.scheme,
        host: target.host,
        ports: Object.freeze([...target.ports]),
        path_prefixes: Object.freeze([...target.path_prefixes]),
      }),
    ),
  );
  const supportingHosts = Object.freeze(
    value.network.supporting_hosts.map((host) =>
      Object.freeze({
        scheme: host.scheme,
        host: host.host,
        ports: Object.freeze([...host.ports]),
        allowed_methods: Object.freeze([...host.allowed_methods]),
        capture: host.capture,
      }),
    ),
  );
  return Object.freeze({
    schema_version: 1,
    source: Object.freeze({ ...value.source }),
    program: Object.freeze({ ...value.program }),
    policy: Object.freeze({ ...value.policy }),
    network: Object.freeze({
      targets,
      supporting_hosts: supportingHosts,
      blocked_hosts: Object.freeze([...value.network.blocked_hosts]),
    }),
  });
}
