/**
 * Which certificate authorities this process trusts.
 *
 * Node trusts the list it was built with and nothing else. A machine on a
 * network that inspects TLS has that network's authority installed in the
 * operating system — which is why its browser works — and every request this
 * process makes fails there with an untrusted-certificate error. So the
 * launcher adds the operating system's store, and any file the user names, to
 * what Node already trusts, before the first request is made.
 */
import { readFileSync } from 'node:fs'
import tls from 'node:tls'

/** The launch-environment layers a trust setting may come from. */
const TRUSTED_LAYERS = ['process', 'user-env'] as const

/**
 * The part of the launcher's environment snapshot this module reads. A
 * project's own `.env` arrives with a clone, so it is never asked: a
 * repository must not choose whom the harness trusts.
 */
export interface TrustEnvironment {
  getFrom(name: string, sources: readonly ('process' | 'project-env' | 'user-env')[]): { readonly value: string } | undefined
}

/** The slice of `node:tls` used here, so a test can stand in for it. */
export interface TrustApi {
  getCACertificates?: ((type: 'default' | 'system') => string[]) | undefined
  setDefaultCACertificates?: ((certificates: string[]) => void) | undefined
}

const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g

/** What was added to the trusted authorities. */
export interface TrustSummary {
  /** Authorities taken from the operating system's store that Node did not already trust. */
  system: number
  /** Authorities taken from the file named by `NODE_EXTRA_CA_CERTS`. */
  extra: number
}

/**
 * Trust the operating system's certificate authorities, and those in the file
 * `NODE_EXTRA_CA_CERTS` names, in addition to Node's own.
 *
 * `NODE_EXTRA_CA_CERTS` is read here as well as by Node because Node samples
 * it once, at start, from the real environment: a value written in the
 * Harness home's `.env` would otherwise never take effect. Set
 * `DSH_TRUST_SYSTEM_CA=0` to leave the operating system's store out.
 *
 * Nothing here can stop the launch: a store that cannot be read is reported
 * and skipped, and requests then fail the way they did before.
 *
 * @param env - the launch environment snapshot.
 * @param report - receives one operator-facing line per problem.
 * @param api - `node:tls`, injectable for tests.
 * @param readFile - reads the named file, injectable for tests.
 * @returns how many authorities each source added.
 */
export function trustLocalAuthorities(
  env: TrustEnvironment,
  report: (message: string) => void,
  api: TrustApi = tls as TrustApi,
  readFile: (path: string) => string = path => readFileSync(path, 'utf8'),
): TrustSummary {
  const summary: TrustSummary = { system: 0, extra: 0 }
  // Older runtimes cannot change the default list; they keep Node's own.
  if (typeof api.getCACertificates !== 'function' || typeof api.setDefaultCACertificates !== 'function') return summary

  const trusted = new Set(api.getCACertificates('default'))
  const before = trusted.size
  const optOut = env.getFrom('DSH_TRUST_SYSTEM_CA', TRUSTED_LAYERS)?.value.trim().toLowerCase()
  if (optOut !== '0' && optOut !== 'false') {
    try {
      for (const certificate of api.getCACertificates('system')) trusted.add(certificate)
    } catch (error) {
      report(`the operating system's certificate store could not be read (${error instanceof Error ? error.message : String(error)}); only the built-in authorities are trusted`)
    }
  }
  summary.system = trusted.size - before

  const extraPath = env.getFrom('NODE_EXTRA_CA_CERTS', TRUSTED_LAYERS)?.value.trim()
  if (extraPath !== undefined && extraPath !== '') {
    try {
      const found = readFile(extraPath).match(PEM_CERTIFICATE) ?? []
      if (found.length === 0) report('NODE_EXTRA_CA_CERTS names a file that holds no PEM certificate; it adds no trusted authority')
      const withSystem = trusted.size
      for (const certificate of found) trusted.add(certificate)
      summary.extra = trusted.size - withSystem
    } catch (error) {
      report(`NODE_EXTRA_CA_CERTS could not be read (${error instanceof Error ? error.message : String(error)}); it adds no trusted authority`)
    }
  }

  if (trusted.size === before) return summary
  try {
    api.setDefaultCACertificates([...trusted])
  } catch (error) {
    report(`the trusted certificate authorities could not be extended (${error instanceof Error ? error.message : String(error)})`)
    return { system: 0, extra: 0 }
  }
  return summary
}
