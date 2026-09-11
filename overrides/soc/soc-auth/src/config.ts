/**
 * Plugin configuration checking, kept free of `@deepseek-ai/*` imports so it can
 * be unit tested on its own.
 *
 * A preset row may carry no `config:` block at all, in which case Cordis calls
 * `apply(ctx, undefined)`. Reading a field off that yields
 * "Cannot read properties of undefined", which tells whoever is editing the
 * preset nothing. Say what is missing instead.
 *
 * @module @deepseek-ai/dsh-soc-auth/config
 */

/** Fields a deployment must supply; the rest have defaults. */
export const REQUIRED_CONFIG_KEYS = ['iamUrl', 'clientId', 'redirectUri', 'soarBaseUrl'] as const

export type RequiredConfigKey = typeof REQUIRED_CONFIG_KEYS[number]

/**
 * Check a `soc-auth` preset row's config.
 * @param config - the row's `config:` block, or `undefined` when it has none.
 * @returns the same config, once every required field is present.
 * @throws when the block is missing or a required field is absent or blank.
 */
export function requireConfig<T extends Partial<Record<RequiredConfigKey, string>>>(
  config: T | undefined,
): T {
  if (config === undefined) {
    throw new Error(
      'soc-auth: this preset row needs a `config:` block with '
      + `${REQUIRED_CONFIG_KEYS.join(', ')}.`,
    )
  }
  const missing = REQUIRED_CONFIG_KEYS.filter(key => {
    const value = config[key]
    return typeof value !== 'string' || value.trim() === ''
  })
  if (missing.length > 0) {
    throw new Error(`soc-auth: config is missing ${missing.join(', ')}.`)
  }
  return config
}
