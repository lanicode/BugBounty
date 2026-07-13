import type { ProgramSourceSnapshot } from "../../packages/platform-source/types.js";

export function snapshotValue(): ProgramSourceSnapshot {
  return {
    schema_version: 1,
    source: {
      kind: "offline_fixture",
      platform: "hackerone",
      source_revision: "fixture-001",
      retrieved_at: "2026-07-13T12:00:00Z",
    },
    program: {
      handle: "local_fixture_program",
      display_name: "Local Fixture Program",
    },
    policy: { content_sha256: "b".repeat(64) },
    network: {
      targets: [
        {
          scheme: "https",
          host: "app.example.test",
          ports: [443],
          path_prefixes: ["/"],
        },
        {
          scheme: "https",
          host: "api.example.test",
          ports: [443],
          path_prefixes: ["/api/"],
        },
      ],
      supporting_hosts: [
        {
          scheme: "https",
          host: "cdn.example.test",
          ports: [443],
          allowed_methods: ["HEAD", "GET"],
          capture: "metadata_only",
        },
      ],
      blocked_hosts: ["blocked.example.test"],
    },
  };
}
