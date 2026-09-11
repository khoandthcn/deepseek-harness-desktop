import { defineConfig } from 'vitest/config'

/**
 * Local-only config: the patcher copies just package.json, tsconfig.json, src
 * and tests into the checkout, so this file never travels.
 *
 * `integration.spec.ts` and `preset.spec.ts` mount real Cordis plugins and so only
 * resolves inside the upstream workspace, where `pnpm vitest run packages/soc`
 * runs it. Running the unit specs here needs no workspace, so exclude it.
 */
export default defineConfig({
  test: {
    exclude: ['**/node_modules/**', 'tests/integration.spec.ts', 'tests/preset.spec.ts'],
  },
})
