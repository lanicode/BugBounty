import { DatabaseSync } from "node:sqlite";
import { canonicalJson, sha256 } from "./canonical.js";
import { SecurityError } from "./errors.js";

type SchemaRow = Readonly<Record<string, unknown>>;
type SchemaQuery = (sql: string) => readonly SchemaRow[];

export interface SqliteSchemaExpectation {
  readonly objectNames: readonly string[];
  readonly profile: Readonly<Record<string, unknown>>;
  readonly digest: string;
}

interface BuildSqliteSchemaExpectationOptions {
  readonly statements: readonly string[];
  readonly prerequisites?: readonly string[];
}

/**
 * Builds the trusted reference from the owned DDL in an isolated in-memory
 * database. The resulting profile includes canonical sqlite_schema SQL,
 * columns, STRICT/WITHOUT ROWID flags, indexes and foreign-key bindings.
 */
export function buildSqliteSchemaExpectation(
  options: BuildSqliteSchemaExpectationOptions,
): SqliteSchemaExpectation {
  const objectNames = schemaObjectNames(options.statements);
  const tableNames = schemaTableNames(options.statements);
  const reference = new DatabaseSync(":memory:", {
    allowExtension: false,
    enableDoubleQuotedStringLiterals: false,
    enableForeignKeyConstraints: false,
  });
  try {
    for (const prerequisite of options.prerequisites ?? [])
      reference.exec(prerequisite);
    for (const statement of options.statements) reference.exec(statement);
    const profile = captureSchemaProfile(
      (sql) => reference.prepare(sql).all(),
      objectNames,
      tableNames,
    );
    return Object.freeze({
      objectNames,
      profile,
      digest: sha256(canonicalJson(profile)),
    });
  } finally {
    reference.close();
  }
}

/** Verifies the live schema without repairing or widening it. */
export function assertExactSqliteSchema(
  query: SchemaQuery,
  expectation: SqliteSchemaExpectation,
  errorCode: string,
): void {
  try {
    const tableNames = expectation.profile["tableNames"];
    if (
      !Array.isArray(tableNames) ||
      tableNames.some((name) => typeof name !== "string")
    )
      throw new Error("SQLITE_SCHEMA_EXPECTATION_INVALID");
    const actual = captureSchemaProfile(
      query,
      expectation.objectNames,
      tableNames,
    );
    if (canonicalJson(actual) !== canonicalJson(expectation.profile))
      throw new Error("SQLITE_SCHEMA_PROFILE_MISMATCH");
  } catch {
    throw new SecurityError(errorCode);
  }
}

/**
 * Used before first-time creation so a partial pre-existing namespace is not
 * adopted as a fresh trusted schema.
 */
export function assertSqliteSchemaNamespaceEmpty(
  query: SchemaQuery,
  expectation: SqliteSchemaExpectation,
  errorCode: string,
): void {
  try {
    for (const name of expectation.objectNames) {
      const rows = query(
        `SELECT name FROM sqlite_schema WHERE name=${quotedLiteral(name)}`,
      );
      if (rows.length !== 0) throw new Error("SQLITE_SCHEMA_OBJECT_EXISTS");
    }
  } catch {
    throw new SecurityError(errorCode);
  }
}

function captureSchemaProfile(
  query: SchemaQuery,
  objectNames: readonly string[],
  tableNames: readonly string[],
): Readonly<Record<string, unknown>> {
  const objects = objectNames.map((name) => {
    const rows = query(
      `SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name=${quotedLiteral(name)}`,
    );
    if (rows.length !== 1) throw new Error("SQLITE_SCHEMA_OBJECT_INVALID");
    const row = rows[0];
    if (row === undefined) throw new Error("SQLITE_SCHEMA_OBJECT_INVALID");
    return Object.freeze({
      type: requiredString(row["type"]),
      name: requiredString(row["name"]),
      tableName: requiredString(row["tbl_name"]),
      sql: requiredString(row["sql"]),
    });
  });
  const tables = tableNames.map((name) => captureTableProfile(query, name));
  return Object.freeze({
    objectNames: Object.freeze([...objectNames]),
    tableNames: Object.freeze([...tableNames]),
    objects: Object.freeze(objects),
    tables: Object.freeze(tables),
  });
}

function captureTableProfile(
  query: SchemaQuery,
  tableName: string,
): Readonly<Record<string, unknown>> {
  const quotedTable = quotedIdentifier(tableName);
  const tableList = query(`PRAGMA main.table_list(${quotedTable})`);
  if (tableList.length !== 1)
    throw new Error("SQLITE_SCHEMA_TABLE_METADATA_INVALID");
  const table = tableList[0];
  if (table === undefined)
    throw new Error("SQLITE_SCHEMA_TABLE_METADATA_INVALID");

  const columns = query(`PRAGMA main.table_xinfo(${quotedTable})`).map((row) =>
    Object.freeze({
      cid: requiredInteger(row["cid"]),
      name: requiredString(row["name"]),
      type: requiredString(row["type"]),
      notNull: requiredInteger(row["notnull"]),
      defaultValue: nullableString(row["dflt_value"]),
      primaryKeyPosition: requiredInteger(row["pk"]),
      hidden: requiredInteger(row["hidden"]),
    }),
  );
  if (columns.length === 0)
    throw new Error("SQLITE_SCHEMA_TABLE_COLUMNS_INVALID");

  const indexes = query(`PRAGMA main.index_list(${quotedTable})`)
    .map((row) => {
      const indexName = requiredIdentifier(row["name"]);
      const schemaRows = query(
        `SELECT sql FROM sqlite_schema WHERE type='index' AND name=${quotedLiteral(indexName)}`,
      );
      if (schemaRows.length !== 1)
        throw new Error("SQLITE_SCHEMA_INDEX_INVALID");
      const schemaRow = schemaRows[0];
      if (schemaRow === undefined)
        throw new Error("SQLITE_SCHEMA_INDEX_INVALID");
      const indexColumns = query(
        `PRAGMA main.index_xinfo(${quotedIdentifier(indexName)})`,
      ).map((column) =>
        Object.freeze({
          sequence: requiredInteger(column["seqno"]),
          columnId: requiredInteger(column["cid"]),
          name: nullableString(column["name"]),
          descending: requiredInteger(column["desc"]),
          collation: requiredString(column["coll"]),
          key: requiredInteger(column["key"]),
        }),
      );
      return Object.freeze({
        name: indexName,
        unique: requiredInteger(row["unique"]),
        origin: requiredString(row["origin"]),
        partial: requiredInteger(row["partial"]),
        sql: nullableString(schemaRow["sql"]),
        columns: Object.freeze(indexColumns),
      });
    })
    .sort((left, right) => left.name.localeCompare(right.name));

  const foreignKeys = query(`PRAGMA main.foreign_key_list(${quotedTable})`)
    .map((row) =>
      Object.freeze({
        id: requiredInteger(row["id"]),
        sequence: requiredInteger(row["seq"]),
        targetTable: requiredString(row["table"]),
        from: requiredString(row["from"]),
        to: nullableString(row["to"]),
        onUpdate: requiredString(row["on_update"]),
        onDelete: requiredString(row["on_delete"]),
        match: requiredString(row["match"]),
      }),
    )
    .sort(
      (left, right) => left.id - right.id || left.sequence - right.sequence,
    );

  return Object.freeze({
    name: tableName,
    tableList: Object.freeze({
      schema: requiredString(table["schema"]),
      name: requiredString(table["name"]),
      type: requiredString(table["type"]),
      columnCount: requiredInteger(table["ncol"]),
      withoutRowId: requiredInteger(table["wr"]),
      strict: requiredInteger(table["strict"]),
    }),
    columns: Object.freeze(columns),
    indexes: Object.freeze(indexes),
    foreignKeys: Object.freeze(foreignKeys),
  });
}

function schemaObjectNames(statements: readonly string[]): readonly string[] {
  const names = statements.map((statement) => {
    const match =
      /^CREATE\s+(?:TABLE|TRIGGER)\s+IF\s+NOT\s+EXISTS\s+([a-z][a-z0-9_]*)\b/u.exec(
        statement.trim(),
      );
    if (match?.[1] === undefined)
      throw new Error("SQLITE_SCHEMA_STATEMENT_INVALID");
    return match[1];
  });
  if (new Set(names).size !== names.length)
    throw new Error("SQLITE_SCHEMA_OBJECT_DUPLICATE");
  return Object.freeze([...names].sort());
}

function schemaTableNames(statements: readonly string[]): readonly string[] {
  return Object.freeze(
    statements
      .map((statement) =>
        /^CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([a-z][a-z0-9_]*)\b/u.exec(
          statement.trim(),
        ),
      )
      .flatMap((match) => (match?.[1] === undefined ? [] : [match[1]]))
      .sort(),
  );
}

function requiredIdentifier(value: unknown): string {
  const result = requiredString(value);
  if (!/^[a-z][a-z0-9_]*$/u.test(result))
    throw new Error("SQLITE_SCHEMA_IDENTIFIER_INVALID");
  return result;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string") throw new Error("SQLITE_SCHEMA_VALUE_INVALID");
  return value;
}

function nullableString(value: unknown): string | null {
  if (value === null) return null;
  return requiredString(value);
}

function requiredInteger(value: unknown): number {
  const result =
    typeof value === "bigint" &&
    value >= BigInt(Number.MIN_SAFE_INTEGER) &&
    value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : value;
  if (typeof result !== "number" || !Number.isSafeInteger(result))
    throw new Error("SQLITE_SCHEMA_INTEGER_INVALID");
  return result;
}

function quotedIdentifier(value: string): string {
  if (!/^[a-z][a-z0-9_]*$/u.test(value))
    throw new Error("SQLITE_SCHEMA_IDENTIFIER_INVALID");
  return `"${value}"`;
}

function quotedLiteral(value: string): string {
  if (!/^[a-z][a-z0-9_]*$/u.test(value))
    throw new Error("SQLITE_SCHEMA_IDENTIFIER_INVALID");
  return `'${value}'`;
}
