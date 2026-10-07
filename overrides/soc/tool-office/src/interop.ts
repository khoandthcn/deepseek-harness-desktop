/**
 * A CommonJS package's export, however the loader hands it over. Node's ESM
 * loader, a bundler and vitest each wrap `module.exports` differently: as the
 * default import itself, or under a `default` key one level down.
 */
export function cjs<T>(imported: unknown): T {
  const value = imported as { default?: unknown, __esModule?: boolean } | null
  if (value !== null && typeof value === 'object' && 'default' in value && value.default !== undefined) {
    const inner = value.default as { default?: unknown } | null
    // A transpiled module can nest it twice: { default: { default: fn } }.
    if (inner !== null && typeof inner === 'object' && 'default' in inner && typeof inner.default === 'function') return inner.default as T
    return value.default as T
  }
  return imported as T
}
