/**
 * Which certificate authorities this process trusts.
 *
 * Node trusts the list it was built with and nothing else. A machine on a
 * network that inspects TLS has that network's authority installed in the
 * operating system — which is why its browser works — and every request this
 * process makes fails there with an untrusted-certificate error. So the
 * launcher adds the operating system's store, and the certificates the user
 * puts in the Harness home's `certs` folder, to what Node already trusts,
 * before the first request is made.
 *
 * A folder, not a variable: the Harness home's `.env` may not name
 * `NODE_EXTRA_CA_CERTS` (the launcher refuses to start rather than let a file
 * change what is trusted), and setting a variable for a desktop application is
 * harder for most people than copying one file. `NODE_EXTRA_CA_CERTS` set in
 * the launching environment still works, read by Node itself.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { X509Certificate } from 'node:crypto'
import { join } from 'node:path'
import tls from 'node:tls'

/**
 * The part of the launcher's environment snapshot this module reads. Only the
 * inherited process environment is asked: no `.env` file may switch trust off.
 */
export interface TrustEnvironment {
  getFrom(name: string, sources: readonly ('process' | 'project-env' | 'user-env')[]): { readonly value: string } | undefined
}

/** The slice of `node:tls` used here, so a test can stand in for it. */
export interface TrustApi {
  getCACertificates?: ((type: 'default' | 'system') => string[]) | undefined
  setDefaultCACertificates?: ((certificates: string[]) => void) | undefined
}

/** The folder under the Harness home whose certificates are trusted. */
export const CERTS_DIR = 'certs'

/** File endings read from that folder. */
const CERT_FILE = /\.(pem|crt|cer)$/i

const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g

/** What was added to the trusted authorities. */
export interface TrustSummary {
  /** Authorities taken from the operating system's store that Node did not already trust. */
  system: number
  /** Authorities taken from the files in the Harness home's `certs` folder. */
  files: number
}

export interface TrustOptions {
  /** The Harness home; its `certs` folder is read. Omitted: no folder is read. */
  home?: string | undefined
  /** `node:tls`, injectable for tests. */
  api?: TrustApi | undefined
  /** Reads one file, injectable for tests. */
  readFile?: ((path: string) => Buffer) | undefined
  /** Lists one folder, injectable for tests. */
  listDir?: ((path: string) => string[]) | undefined
}

/**
 * The certificates in one file: PEM, one or many, or a single DER certificate
 * as Windows exports a `.cer` or `.crt` by default.
 * @returns the certificates in PEM form; empty when the file holds none.
 */
export function certificatesIn(bytes: Buffer): string[] {
  const text = bytes.toString('latin1')
  const pem = text.match(PEM_CERTIFICATE)
  if (pem) return pem.map(block => block.replace(/\r\n/g, '\n'))
  try {
    return [new X509Certificate(bytes).toString().trim()]
  } catch {
    return []
  }
}

/**
 * Trust the operating system's certificate authorities, and those in the
 * Harness home's `certs` folder, in addition to Node's own.
 *
 * Set `DSH_TRUST_SYSTEM_CA=0` in the launching environment to leave the
 * operating system's store out. Nothing here can stop the launch: a store or
 * file that cannot be read is reported and skipped.
 *
 * @param env - the launch environment snapshot.
 * @param report - receives one operator-facing line per problem.
 * @param options - the Harness home, and test seams.
 * @returns how many authorities each source added.
 */
export function trustLocalAuthorities(
  env: TrustEnvironment,
  report: (message: string) => void,
  options: TrustOptions = {},
): TrustSummary {
  const api = options.api ?? (tls as TrustApi)
  const readFile = options.readFile ?? (path => readFileSync(path))
  const listDir = options.listDir ?? (path => readdirSync(path))
  const summary: TrustSummary = { system: 0, files: 0 }
  // Older runtimes cannot change the default list; they keep Node's own.
  if (typeof api.getCACertificates !== 'function' || typeof api.setDefaultCACertificates !== 'function') return summary

  const trusted = new Set(api.getCACertificates('default'))
  const before = trusted.size
  const optOut = env.getFrom('DSH_TRUST_SYSTEM_CA', ['process'])?.value.trim().toLowerCase()
  if (optOut !== '0' && optOut !== 'false') {
    try {
      for (const certificate of api.getCACertificates('system')) trusted.add(certificate)
    } catch (error) {
      report(`the operating system's certificate store could not be read (${error instanceof Error ? error.message : String(error)}); only the built-in authorities are trusted`)
    }
  }
  summary.system = trusted.size - before

  if (options.home !== undefined) {
    const folder = join(options.home, CERTS_DIR)
    let names: string[] = []
    try {
      names = listDir(folder).filter(name => CERT_FILE.test(name)).sort()
    } catch (error) {
      if ((error as NodeJS.ErrnoException | null)?.code !== 'ENOENT') {
        report(`${folder} could not be read (${error instanceof Error ? error.message : String(error)}); its certificates are not trusted`)
      }
    }
    const withSystem = trusted.size
    for (const name of names) {
      try {
        const found = certificatesIn(readFile(join(folder, name)))
        if (found.length === 0) report(`${join(folder, name)} holds no certificate (PEM or DER); it adds no trusted authority`)
        for (const certificate of found) trusted.add(certificate)
      } catch (error) {
        report(`${join(folder, name)} could not be read (${error instanceof Error ? error.message : String(error)})`)
      }
    }
    summary.files = trusted.size - withSystem
  }

  if (trusted.size === before) return summary
  try {
    api.setDefaultCACertificates([...trusted])
  } catch (error) {
    report(`the trusted certificate authorities could not be extended (${error instanceof Error ? error.message : String(error)})`)
    return { system: 0, files: 0 }
  }
  return summary
}
