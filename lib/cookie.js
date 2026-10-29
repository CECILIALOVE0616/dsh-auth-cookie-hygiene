import { createHash } from 'node:crypto'

export const COOKIE_PREFIX = 'dsh-auth-'

/**
 * Browser auth cookies minted by dsh-client-connection have the shape:
 *   dsh-auth-<base64url(sha256(authority))>=v1.<base64url(json)>.<base64url(hmac)>
 * The signature uses DSH's persistent credential secret; this plugin does not
 * read it. We only make claims about the v1 payload that are self-consistent and
 * bound to a loopback authority; everything else is kept.
 */
export const COOKIE_NAME_RE = /^dsh-auth-[A-Za-z0-9_-]{43}$/

const BASE64URL_RE = /^[A-Za-z0-9_-]*$/
const LOCAL_AUTHORITY_RE = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/
const MAX_COOKIE_VALUE_BYTES = 4096
const MAX_PAYLOAD_BYTES = 2048
const MAX_AUTHORITY_LENGTH = 64
const EXPIRES_AT = 'Thu, 01 Jan 1970 00:00:00 GMT'

export function encodeBase64Url(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/u, '')
}

export function cookieNameForAuthority(authority) {
  const digest = createHash('sha256').update(String(authority)).digest()
  return `${COOKIE_PREFIX}${encodeBase64Url(digest)}`
}

export function decodeBase64UrlStrict(value, maxDecodedBytes = MAX_PAYLOAD_BYTES) {
  if (typeof value !== 'string' || !BASE64URL_RE.test(value)) return null
  if (value.length % 4 === 1) return null
  const padded = value + '='.repeat((4 - (value.length % 4)) % 4)
  let buffer
  try {
    buffer = Buffer.from(padded, 'base64')
  } catch {
    return null
  }
  if (buffer.length > maxDecodedBytes) return null
  // Reject non-canonical encodings (e.g. trailing bits) and accidental std base64.
  if (encodeBase64Url(buffer) !== value) return null
  return buffer
}

/**
 * Parse a Cookie request header without ever touching the network.
 * Only the first maxBytes / maxPairs are inspected; this bounds malicious input.
 */
export function collectCookiePairs(header, { maxBytes = 262144, maxPairs = 512 } = {}) {
  if (typeof header !== 'string' || header.length === 0) return []
  const text = header.length > maxBytes ? header.slice(0, maxBytes) : header
  const pairs = []
  for (const segment of text.split(';')) {
    if (pairs.length >= maxPairs) break
    const eq = segment.indexOf('=')
    if (eq <= 0) continue
    const name = segment.slice(0, eq).trim()
    if (name.length === 0 || name.length > 256) continue
    let value = segment.slice(eq + 1).trim()
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1)
    }
    pairs.push({ name, value })
  }
  return pairs
}

export function isLoopback127Authority(authority) {
  if (typeof authority !== 'string' || authority.length > MAX_AUTHORITY_LENGTH) return false
  const match = LOCAL_AUTHORITY_RE.exec(authority)
  if (!match) return false
  const port = Number(match[1])
  return port >= 1 && port <= 65535
}

/**
 * Validate a browser cookie as a self-consistent v1 auth cookie for a
 * 127.0.0.1:<port> authority. Returns null for anything we must not touch.
 * `signature` is checked only for shape (43 base64url chars); it cannot be
 * verified without reading the Host's stored credential secret.
 */
export function classifyBrowserAuthCookie(name, value) {
  try {
    if (typeof name !== 'string' || !COOKIE_NAME_RE.test(name)) return null
    if (typeof value !== 'string' || value.length > MAX_COOKIE_VALUE_BYTES) return null
    const parts = value.split('.')
    if (parts.length !== 3) return null
    const [version, body, signature] = parts
    if (version !== 'v1') return null
    if (body.length === 0 || body.length > MAX_PAYLOAD_BYTES) return null
    if (signature.length !== 43 || !BASE64URL_RE.test(signature)) return null
    const raw = decodeBase64UrlStrict(body)
    if (!raw) return null

    let payload
    try {
      payload = JSON.parse(raw.toString('utf8'))
    } catch {
      return null
    }
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return null
    if (payload.version !== 1) return null

    const authority = payload.authority
    if (!isLoopback127Authority(authority)) return null
    if (payload.issuedAt !== undefined && !Number.isSafeInteger(payload.issuedAt)) return null
    if (!Number.isSafeInteger(payload.expiresAt)) return null
    if (!Number.isSafeInteger(payload.issuedAt)) return null
    if (payload.expiresAt <= payload.issuedAt) return null
    if (payload.issuedAt <= 0) return null

    // The cookie name is the hash of the authority; a mismatch means this is
    // not a cookie the local Host itself would have minted for that authority.
    if (cookieNameForAuthority(authority) !== name) return null

    return {
      name,
      authority,
      port: Number(LOCAL_AUTHORITY_RE.exec(authority)[1]),
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt,
    }
  } catch {
    return null
  }
}

export function buildExpirySetCookie(name, { secure = false } = {}) {
  if (!COOKIE_NAME_RE.test(name)) throw new TypeError('not a dsh-auth cookie name')
  return (
    `${name}=; Max-Age=0; Path=/; Expires=${EXPIRES_AT}; ` +
    `HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`
  )
}

export function normalizeSetCookie(value) {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) {
    const out = []
    for (const item of value) {
      if (typeof item === 'string') out.push(item)
    }
    return out
  }
  return []
}

/** Merge Set-Cookie sources, keeping first occurrence order and stripping exact duplicates. */
export function mergeSetCookieHeaders(...sources) {
  const seen = new Set()
  const out = []
  for (const source of sources) {
    for (const value of normalizeSetCookie(source)) {
      if (seen.has(value)) continue
      seen.add(value)
      out.push(value)
    }
  }
  return out
}

/** Conservative byte estimate for an outgoing Set-Cookie list (value bytes + header framing). */
export function setCookieBytes(values) {
  let bytes = 0
  for (const value of normalizeSetCookie(values)) {
    bytes += Buffer.byteLength(value, 'utf8') + 16
  }
  return bytes
}

export const cookieInternals = Object.freeze({
  MAX_COOKIE_VALUE_BYTES,
  MAX_PAYLOAD_BYTES,
  MAX_AUTHORITY_LENGTH,
})
