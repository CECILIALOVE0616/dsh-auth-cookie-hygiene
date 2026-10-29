import http from 'node:http'
import { cookieNameForAuthority, encodeBase64Url } from '../lib/cookie.js'
import { installServerHook } from '../lib/hook.js'

export const SIG = 'A'.repeat(43)

export function makeAuthCookie(authority, overrides = {}) {
  const {
    version = 1,
    name = cookieNameForAuthority(authority),
    signature = SIG,
    issuedAt = Date.now() - 1000,
    expiresAt = Date.now() + 3_600_000,
    payload = {},
  } = overrides
  const body = encodeBase64Url(
    Buffer.from(JSON.stringify({ version, authority, issuedAt, expiresAt, ...payload })),
  )
  return { name, value: `v${version}.${body}.${signature}`, authority }
}

export function cookieHeader(...cookies) {
  return cookies
    .flat()
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join('; ')
}

export function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function waitFor(check, { timeout = 2000, interval = 10, label = 'condition' } = {}) {
  const started = Date.now()
  let lastError
  while (Date.now() - started < timeout) {
    try {
      if (await check()) return true
    } catch (error) {
      lastError = error
    }
    await delay(interval)
  }
  throw new Error(
    `timed out waiting for ${label}${lastError ? ` (last error: ${lastError.message})` : ''}`,
  )
}

export async function listen(handler) {
  const server = http.createServer(
    handler ||
      ((req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('ok')
      }),
  )
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return server
}

export async function close(server) {
  if (!server || !server.listening) return
  await new Promise((resolve) => server.close(resolve))
}

export function request(server, { path = '/', method = 'GET', headers = {}, cookies } = {}) {
  const { port } = server.address()
  const mergedHeaders = { host: `127.0.0.1:${port}`, ...headers }
  if (cookies) mergedHeaders.cookie = cookieHeader(cookies)
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path,
        method,
        headers: mergedHeaders,
        agent: false,
      },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        })
      },
    )
    req.on('error', reject)
    req.end()
  })
}

export function setCookiesOf(response) {
  const value = response.headers['set-cookie']
  if (!value) return []
  return Array.isArray(value) ? value : [value]
}

export function setCookieName(value) {
  const eq = value.indexOf('=')
  return eq === -1 ? value : value.slice(0, eq)
}

export async function startHookedServer({ handler, hookOptions = {}, liveness } = {}) {
  const server = await listen(handler)
  const hook = installServerHook(server, { liveness, ...hookOptions })
  const { port } = server.address()
  return { server, hook, port, authority: `127.0.0.1:${port}` }
}
