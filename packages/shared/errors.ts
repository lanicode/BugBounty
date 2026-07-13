export class SecurityError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "SecurityError";
  }
}

export function errorCode(error: unknown): string {
  return error instanceof SecurityError
    ? error.code
    : "INTERNAL_SECURITY_ERROR";
}
