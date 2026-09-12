import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'

/**
 * Local-only config: the patcher copies just package.json, tsconfig.json, src
 * and tests into the checkout, so this file never travels.
 *
 * `@deepseek-ai/dsh-soc-client` is a workspace sibling; outside the checkout
 * there is no workspace, so point the name at its source directly.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@deepseek-ai/dsh-soc-client': resolve(import.meta.dirname, '../soc-client/src/index.ts'),
    },
  },
})
