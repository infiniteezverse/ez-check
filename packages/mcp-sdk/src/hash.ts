import { createHash } from 'node:crypto';

/** JSON with object keys sorted at every level, so equal values always hash the same. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object' && !(value instanceof Date)) {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => [key, sortKeys((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}

/** sha256 over the tool name and its canonical arguments, hex encoded. */
export function hashToolCall(tool: string, args: unknown): string {
  return createHash('sha256')
    .update(canonicalJson({ tool, args }))
    .digest('hex');
}
