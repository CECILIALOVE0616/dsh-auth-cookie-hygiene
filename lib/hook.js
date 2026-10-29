import {
  buildExpirySetCookie,
  classifyBrowserAuthCookie,
  collectCookiePairs,
  cookieNameForAuthority,
  mergeSetCookieHeaders,
  setCookieBytes,
} from './cookie.js'
import { PortLiveness } from './liveness.js'

const INSTALL_MARK = Symbol.for('dsh-auth-cookie-hygiene.install')
const RESPONSE_MARK = Symbol.for('dsh-auth-cookie-hygiene.response')

export const hookDefaults = Object.freeze({
  maxPerResponse: 8,
  maxExtraHeaderBytes: 3072,
  maxCandidatesPerRequest: 64,
  recentTtlMs: 5 * 60_000,
  maxRecent: 512,
  confirmTimeoutMs: 700,
})

function intInRange(value, fallback, min, max) {
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback
}

function requestPath(req) {
  const raw = typeof req.url === 'string' && req.url.length > 0 ? req.url : '/'
  const query = raw.indexOf('?')
  const path = query === -1 ? raw : raw.slice(0, query)
  return path === '' ? '/' : path
}

function parseWriteHead(args) {
  const statusCode = args[0]
  const second = args[1]
  if (typeof second === 'string') {
    return { statusCode, statusMessage: second, headers: args[2] }
  }
  return { statusCode, statusMessage: undefined, headers: second }
}

function splitSetCookie(headers) {
  if (headers === undefined || headers === null) {
    return { clean: undefined, setCookie: undefined, supported: true }
  }
  if (typeof headers !== 'object' || Array.isArray(headers)) {
    return { clean: undefined, setCookie: undefined, supported: false }
  }
  const proto = Object.getPrototypeOf(headers)
  if (proto !== Object.prototype && proto !== null) {
    return { clean: undefined, setCookie: undefined, supported: false }
  }
  const clean = {}
  let setCookie
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === 'set-cookie') setCookie = headers[key]
    else clean[key] = headers[key]
  }
  return { clean, setCookie, supported: true }
}

/**
 * Install a response-cookie hygiene hook on a Node HTTP server.
 *
 * The hook is a synchronous 'request' listener installed with prependListener,
 * so it runs before the Host's handlers. For a local GET/HEAD index request it
 * starts a fresh bounded port confirmation and gates that one response: the
 * authenticated 200/303 writeHead is held until the confirmation settles, then
 * expiry Set-Cookie headers are merged. The status code, Location, body and
 * existing Set-Cookie values are preserved.
 *
 * @param {import('node:http').Server} server
 * @param {object} [options]
 * @returns {{installed: boolean, dispose: () => void}}
 */
export function installServerHook(server, options = {}) {
  if (
    !server ||
    typeof server.prependListener !== 'function' ||
    typeof server.removeListener !== 'function'
  ) {
    return { installed: false, dispose() {} }
  }

  const existing = server[INSTALL_MARK]
  if (existing) return existing

  const now = typeof options.now === 'function' ? options.now : Date.now
  const logger = options.logger
  const isSecure = typeof options.isSecure === 'function' ? options.isSecure : () => false
  const enabled = options.enabled !== false
  const maxPerResponse = intInRange(options.maxPerResponse, hookDefaults.maxPerResponse, 1, 32)
  const maxExtraHeaderBytes = intInRange(
    options.maxExtraHeaderBytes,
    hookDefaults.maxExtraHeaderBytes,
    256,
    16384,
  )
  const maxCandidatesPerRequest = intInRange(
    options.maxCandidatesPerRequest,
    hookDefaults.maxCandidatesPerRequest,
    1,
    256,
  )
  const recentTtlMs = intInRange(options.recentTtlMs, hookDefaults.recentTtlMs, 0, 60 * 60_000)
  const maxRecent = intInRange(options.maxRecent, hookDefaults.maxRecent, 16, 4096)
  const confirmTimeoutMs = intInRange(
    options.confirmTimeoutMs,
    hookDefaults.confirmTimeoutMs,
    100,
    5000,
  )

  const liveness =
    options.liveness && typeof options.liveness.status === 'function'
      ? options.liveness
      : new PortLiveness(options.liveness || {})
  const ownsLiveness = liveness !== options.liveness

  const recentlySent = new Map()
  const gates = new Set()
  let lastErrorLogAt = 0

  const reportError = (error) => {
    const current = now()
    if (current - lastErrorLogAt < 60_000) return
    lastErrorLogAt = current
    try {
      logger?.warn?.('[dsh-auth-cookie-hygiene] cookie cleanup skipped after internal error', error)
    } catch {
      // logging must never break request handling
    }
  }

  const pruneRecent = (current) => {
    if (recentlySent.size === 0) return
    for (const [name, at] of recentlySent) {
      if (current - at >= recentTtlMs) recentlySent.delete(name)
    }
    while (recentlySent.size > maxRecent) {
      const oldest = recentlySent.keys().next().value
      recentlySent.delete(oldest)
    }
  }

  const confirmPort = (port) => {
    try {
      if (typeof liveness.confirmFresh === 'function') {
        return Promise.resolve(liveness.confirmFresh(port, { timeoutMs: confirmTimeoutMs })).catch(
          () => 'unknown',
        )
      }
      // Test/embedding seam: allow a tiny fake liveness without the async API.
      return Promise.resolve(liveness.status(port)).catch(() => 'unknown')
    } catch {
      return Promise.resolve('unknown')
    }
  }

  const onRequest = (req, res) => {
    try {
      if (!enabled) return
      if (!req || !res || (req.method !== 'GET' && req.method !== 'HEAD')) return
      if (res[RESPONSE_MARK]) return
      const path = requestPath(req)
      if (path !== '/' && path !== '/index.html') return

      const headers = req.headers
      if (!headers) return
      const cookieHeader = headers.cookie
      if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) return
      const host = typeof headers.host === 'string' ? headers.host : ''
      const localHost = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(host)
      if (!localHost || Number(localHost[1]) > 65535 || isSecure()) return
      if (req.socket?.localPort && Number(localHost[1]) !== req.socket.localPort) return

      const currentNames = new Set([cookieNameForAuthority(host)])
      const lowerHost = host.toLowerCase()
      if (lowerHost !== host) currentNames.add(cookieNameForAuthority(lowerHost))

      const pairs = collectCookiePairs(cookieHeader)
      if (pairs.length === 0) return

      const current = now()
      pruneRecent(current)

      const candidates = []
      const seen = new Set()
      for (const pair of pairs) {
        if (candidates.length >= maxCandidatesPerRequest) break
        if (seen.has(pair.name)) continue
        seen.add(pair.name)
        if (currentNames.has(pair.name)) continue
        if (recentlySent.has(pair.name)) continue
        const info = classifyBrowserAuthCookie(pair.name, pair.value)
        if (!info) continue
        // Never touch the authority this request is served for.
        if (info.authority.toLowerCase() === lowerHost) continue
        candidates.push(info)
      }
      if (candidates.length === 0) return

      let gate
      gate = createResponseGate(res, {
        candidates,
        maxPerResponse,
        maxExtraHeaderBytes,
        recentlySent,
        now,
        isSecure,
        confirmTimeoutMs,
        onDone: () => gates.delete(gate),
        onApplied: (chosen) => {
          const stamp = now()
          for (const info of chosen) recentlySent.set(info.name, stamp)
          pruneRecent(stamp)
        },
      })
      if (!gate.isCancelled()) gates.add(gate)

      Promise.all(candidates.map((info) => confirmPort(info.port))).then(
        (results) => {
          if (!gate.isCancelled()) gate.resolve(results)
        },
        (error) => {
          reportError(error)
          if (!gate.isCancelled()) gate.resolve(candidates.map(() => 'unknown'))
        },
      )
    } catch (error) {
      reportError(error)
    }
  }

  server.prependListener('request', onRequest)

  let disposed = false
  const handle = {
    installed: true,
    dispose() {
      if (disposed) return
      disposed = true
      try {
        server.removeListener('request', onRequest)
      } catch {
        // ignore
      }
      for (const gate of [...gates]) gate.cancel()
      gates.clear()
      if (ownsLiveness) liveness.dispose?.()
      recentlySent.clear()
      if (server[INSTALL_MARK] === handle) {
        try {
          delete server[INSTALL_MARK]
        } catch {
          try {
            server[INSTALL_MARK] = undefined
          } catch {
            // non-configurable marker: leave it, the listener is already removed
          }
        }
      }
    },
  }

  try {
    Object.defineProperty(server, INSTALL_MARK, { value: handle, configurable: true })
  } catch {
    // A frozen server cannot be marked; the hook still works and dispose still removes it.
  }

  return handle
}

/**
 * Gate one response until fresh port confirmations settle.
 *
 * The handler keeps its synchronous `authorizeIndex` contract: it may call
 * writeHead/end immediately. We capture those calls, await at most one bounded
 * confirmation, and only then emit the headers. A non-200/303 response (for
 * example 401) is forwarded untouched and immediately.
 */
function createResponseGate(res, options) {
  const {
    candidates,
    maxPerResponse,
    maxExtraHeaderBytes,
    recentlySent,
    now,
    isSecure,
    confirmTimeoutMs,
    onDone,
    onApplied,
  } = options

  const original = {
    writeHead: res.writeHead,
    end: res.end,
    write: res.write,
    flushHeaders: res.flushHeaders,
  }
  if (
    typeof original.writeHead !== 'function' ||
    typeof original.end !== 'function' ||
    typeof res.setHeader !== 'function' ||
    typeof res.getHeader !== 'function'
  ) {
    return {
      resolve() {},
      cancel() {},
      isCancelled: () => true,
    }
  }

  let released = false
  let cancelled = false
  let captured = null
  let endArgs = null
  let results = null
  let timer = null

  const restore = () => {
    try {
      if (res.writeHead === patchedWriteHead) res.writeHead = original.writeHead
      if (res.end === patchedEnd) res.end = original.end
      if (res.write === patchedWrite) res.write = original.write
      if (res.flushHeaders === patchedFlushHeaders) res.flushHeaders = original.flushHeaders
      delete res[RESPONSE_MARK]
      res.off?.('close', onClose)
    } catch {
      // response methods may be frozen; nothing else to do
    }
  }

  const chooseExtras = () => {
    const extras = []
    const chosen = []
    let extraBytes = 0
    for (let i = 0; i < candidates.length; i += 1) {
      if (extras.length >= maxPerResponse) break
      if (results?.[i] !== 'closed') continue
      const info = candidates[i]
      if (recentlySent.has(info.name)) continue
      let value
      try {
        value = buildExpirySetCookie(info.name, { secure: Boolean(isSecure()) })
      } catch {
        continue
      }
      const bytes = setCookieBytes([value])
      if (extraBytes + bytes > maxExtraHeaderBytes) break
      extras.push(value)
      chosen.push(info)
      extraBytes += bytes
    }
    return { extras, chosen }
  }

  const emit = (extras) => {
    if (captured) {
      try {
        if (extras.length === 0) {
          original.writeHead.apply(res, captured.args)
        } else {
        const { statusCode, statusMessage, headers } = captured
        const split = splitSetCookie(headers)
        if (!split.supported) {
          // Unknown header container: preserve the original call and add the
          // expiry through setHeader. Do not rewrite what we cannot parse.
          const existing = res.getHeader('set-cookie')
          const merged = mergeSetCookieHeaders(existing, extras)
          if (merged.length > 0) res.setHeader('Set-Cookie', merged)
          original.writeHead.apply(res, captured.args)
        } else {
          const existing = res.getHeader('set-cookie')
          const merged = mergeSetCookieHeaders(existing, split.setCookie, extras)
          if (merged.length > 0) res.setHeader('Set-Cookie', merged)
          const args = [statusCode]
          if (statusMessage !== undefined) args.push(statusMessage)
          if (split.clean !== undefined) args.push(split.clean)
          original.writeHead.apply(res, args)
        }
        }
      } catch {
        // If header merging fails, fall back to the untouched original call.
        try {
          original.writeHead.apply(res, captured.args)
        } catch {
          // response may already be gone
        }
      }
    } else if (extras.length > 0) {
      // Implicit 200: no writeHead was called, so stash the expiries before end.
      try {
        const existing = res.getHeader('set-cookie')
        res.setHeader('Set-Cookie', mergeSetCookieHeaders(existing, extras))
      } catch {
        // ignore
      }
    }

    if (endArgs) {
      const args = endArgs
      endArgs = null
      try {
        original.end.apply(res, args)
      } catch {
        // ignore
      }
    }
  }

  const release = (allowCleanup = true) => {
    if (released || cancelled) return
    released = true
    if (timer) clearTimeout(timer)
    timer = null
    restore()
    let chosen = []
    let extras = []
    try {
      const picked = allowCleanup ? chooseExtras() : { extras: [], chosen: [] }
      extras = picked.extras
      chosen = picked.chosen
    } catch {
      extras = []
    }
    emit(extras)
    if (chosen.length > 0) {
      try {
        onApplied(chosen)
      } catch {
        // bookkeeping only
      }
    }
    try {
      onDone()
    } catch {
      // ignore
    }
  }

  const maybeRelease = () => {
    if (released || cancelled || results === null) return
    if (!captured && !endArgs) return
    if (!captured) return release(false)
    release()
  }

  const patchedWriteHead = function writeHeadPatched() {
    if (released || cancelled) return original.writeHead.apply(res, arguments)
    if (captured) return res
    const args = Array.from(arguments)
    const parsed = parseWriteHead(args)
    if ((parsed.statusCode !== 200 && parsed.statusCode !== 303) || !splitSetCookie(parsed.headers).supported) {
      // Unauthenticated or unrelated response: no delay, no expiry.
      captured = { ...parsed, args }
      results = results || candidates.map(() => 'unknown')
      release(false)
      return res
    }
    captured = { ...parsed, args }
    maybeRelease()
    return res
  }

  const patchedWrite = function writePatched() {
    if (released || cancelled) return original.write.apply(res, arguments)
    // Never buffer streaming bodies or manufacture successful backpressure.
    release(false)
    return original.write.apply(res, arguments)
  }

  const patchedEnd = function endPatched() {
    if (released || cancelled) return original.end.apply(res, arguments)
    // Only explicit current-DSH 200/303 paths are eligible. Preserve implicit
    // status codes, streaming semantics and other middleware without guessing.
    if (!captured) {
      release(false)
      return original.end.apply(res, arguments)
    }
    if (!endArgs) endArgs = Array.from(arguments)
    maybeRelease()
    return res
  }

  const patchedFlushHeaders = function flushHeadersPatched() {
    if (released || cancelled) return original.flushHeaders?.apply(res, arguments)
    release(false)
    return original.flushHeaders?.apply(res, arguments)
  }

  const onClose = () => {
    if (released || cancelled) return
    cancelled = true
    if (timer) clearTimeout(timer)
    timer = null
    restore()
    endArgs = null
    onDone()
  }

  try {
    Object.defineProperty(res, RESPONSE_MARK, { value: true, configurable: true })
    res.writeHead = patchedWriteHead
    res.write = patchedWrite
    res.end = patchedEnd
    if (original.flushHeaders) res.flushHeaders = patchedFlushHeaders
  } catch {
    restore()
    try {
      onDone()
    } catch {
      // ignore
    }
    return {
      resolve() {},
      cancel() {},
      isCancelled: () => true,
    }
  }

  if (typeof res.once === 'function') res.once('close', onClose)

  timer = setTimeout(() => {
    if (cancelled || released) return
    results = results || candidates.map(() => 'unknown')
    release(false)
  }, confirmTimeoutMs + 100)
  timer.unref?.()

  const cancel = () => {
    if (cancelled || released) return
    // Uninstall must flush a captured response rather than leave it pending.
    release(false)
  }

  return {
    resolve(nextResults) {
      if (cancelled || released) return
      results = nextResults
      maybeRelease()
    },
    cancel,
    isCancelled: () => cancelled || released,
  }
}

export const hookSymbols = Object.freeze({ INSTALL_MARK, RESPONSE_MARK })
