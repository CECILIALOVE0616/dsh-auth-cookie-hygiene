import { hookDefaults, installServerHook } from './hook.js'
import { PortLiveness } from './liveness.js'

export const name = 'dsh-auth-cookie-hygiene'
export const inject = ['webServer']

const DEFAULTS = Object.freeze({
  ...hookDefaults,
  probeTimeoutMs: 250,
  confirmGapMs: 120,
  closedTtlMs: 30_000,
  openTtlMs: 15_000,
  retryBackoffMs: 2_000,
  maxPorts: 256,
  maxRecent: 512,
  serverPollMs: 50,
  serverIdlePollMs: 2_000,
  serverDeadlineMs: 30_000,
  debug: false,
})

function intInRange(value, fallback, min, max) {
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback
}

export function normalizeOptions(config) {
  const source = config && typeof config === 'object' ? config : {}
  return {
    enabled: source.enabled !== false,
    maxPerResponse: intInRange(source.maxPerResponse, DEFAULTS.maxPerResponse, 1, 32),
    maxExtraHeaderBytes: intInRange(
      source.maxExtraHeaderBytes,
      DEFAULTS.maxExtraHeaderBytes,
      256,
      16384,
    ),
    maxCandidatesPerRequest: intInRange(
      source.maxCandidatesPerRequest,
      DEFAULTS.maxCandidatesPerRequest,
      1,
      256,
    ),
    recentTtlMs: intInRange(source.recentTtlMs, DEFAULTS.recentTtlMs, 0, 60 * 60_000),
    maxRecent: intInRange(source.maxRecent, DEFAULTS.maxRecent, 16, 4096),
    confirmTimeoutMs: intInRange(source.confirmTimeoutMs, DEFAULTS.confirmTimeoutMs, 100, 5000),
    probeTimeoutMs: intInRange(source.probeTimeoutMs, DEFAULTS.probeTimeoutMs, 20, 5000),
    confirmGapMs: intInRange(source.confirmGapMs, DEFAULTS.confirmGapMs, 0, 60_000),
    closedTtlMs: intInRange(source.closedTtlMs, DEFAULTS.closedTtlMs, 100, 10 * 60_000),
    openTtlMs: intInRange(source.openTtlMs, DEFAULTS.openTtlMs, 100, 10 * 60_000),
    retryBackoffMs: intInRange(source.retryBackoffMs, DEFAULTS.retryBackoffMs, 50, 60_000),
    maxPorts: intInRange(source.maxPorts, DEFAULTS.maxPorts, 1, 4096),
    serverPollMs: intInRange(source.serverPollMs, DEFAULTS.serverPollMs, 10, 5000),
    serverIdlePollMs: intInRange(source.serverIdlePollMs, DEFAULTS.serverIdlePollMs, 10, 60_000),
    serverDeadlineMs: intInRange(source.serverDeadlineMs, DEFAULTS.serverDeadlineMs, 0, 300_000),
    debug: source.debug === true,
  }
}

/**
 * Watch `webServer.server`, which is a plain field assigned after the service is
 * constructed and listening. A short poll bridges that gap (a static inject makes
 * the service reload on its own lifecycle changes). Any old hook is disposed
 * before a new server is hooked, so HMR cannot stack listeners.
 */
export function watchWebServer(ctx, { options, liveness, logger }) {
  let stopped = false
  let timer = null
  let hook = null
  let attachedServer = null
  let warnedDeadline = false
  let restoreServerProperty = null
  const startedAt = Date.now()

  const getWebServer = () => {
    try {
      return ctx.webServer || null
    } catch {
      return null
    }
  }

  const getServer = () => {
    const webServer = getWebServer()
    try {
      return webServer && webServer.server ? webServer.server : null
    } catch {
      return null
    }
  }

  const attach = (server) => {
    if (stopped) return
    hook?.dispose()
    hook = null
    attachedServer = server
    if (!server || typeof server.prependListener !== 'function') return
    try {
      hook = installServerHook(server, {
        enabled: options.enabled,
        liveness,
        logger,
        maxPerResponse: options.maxPerResponse,
        maxExtraHeaderBytes: options.maxExtraHeaderBytes,
        maxCandidatesPerRequest: options.maxCandidatesPerRequest,
        recentTtlMs: options.recentTtlMs,
        maxRecent: options.maxRecent,
        confirmTimeoutMs: options.confirmTimeoutMs,
        isSecure: () => {
          try {
            return ctx.webServer?.protocol === 'https:'
          } catch {
            return false
          }
        },
      })
      try {
        logger?.info?.('[dsh-auth-cookie-hygiene] attached to web server')
      } catch {
        // logging is optional
      }
    } catch (error) {
      try {
        logger?.warn?.('[dsh-auth-cookie-hygiene] failed to attach; auth cookies are untouched', error)
      } catch {
        // ignore
      }
    }
  }

  /**
   * WebServer assigns its `server` field during async init. If the field is not
   * there yet, replace its own data property with an accessor so we attach at
   * assignment time, before `listen()` can serve the first request. Polling
   * stays as a fallback for unusual field/prototype shapes.
   */
  const installEarlyAccessor = () => {
    const webServer = getWebServer()
    if (!webServer) return
    let current
    try {
      current = webServer.server
    } catch {
      return
    }
    if (current) return

    const own = Object.getOwnPropertyDescriptor(webServer, 'server')
    if (own && (typeof own.get === 'function' || typeof own.set === 'function')) {
      // Do not replace someone else's accessor; polling will pick it up.
      return
    }
    let inheritedAccessor = false
    let proto = Object.getPrototypeOf(webServer)
    while (proto && !inheritedAccessor) {
      const descriptor = Object.getOwnPropertyDescriptor(proto, 'server')
      if (descriptor) {
        inheritedAccessor = Boolean(descriptor.get || descriptor.set)
        break
      }
      proto = Object.getPrototypeOf(proto)
    }
    if (inheritedAccessor) return

    const getter = function getServerProperty() {
      return current
    }
    try {
      Object.defineProperty(webServer, 'server', {
        configurable: true,
        enumerable: own ? own.enumerable !== false : true,
        get: getter,
        set(next) {
          current = next
          if (next) attach(next)
        },
      })
    } catch {
      return
    }

    restoreServerProperty = () => {
      try {
        const descriptor = Object.getOwnPropertyDescriptor(webServer, 'server')
        if (!descriptor || descriptor.get !== getter) return
        if (own) {
          Object.defineProperty(webServer, 'server', {
            ...own,
            value: current,
          })
        } else {
          Object.defineProperty(webServer, 'server', {
            configurable: true,
            enumerable: true,
            writable: true,
            value: current,
          })
        }
      } catch {
        // The field was redefined while we were active; leave the newer shape.
      }
    }
  }

  installEarlyAccessor()

  const tick = () => {
    if (stopped) return
    const server = getServer()
    if (server !== attachedServer) {
      if (server) attach(server)
      else if (hook) {
        hook.dispose()
        hook = null
        attachedServer = null
      }
    }

    if (!attachedServer && options.serverDeadlineMs > 0) {
      if (Date.now() - startedAt > options.serverDeadlineMs) {
        if (!warnedDeadline) {
          warnedDeadline = true
          try {
            logger?.warn?.(
              '[dsh-auth-cookie-hygiene] web server did not appear before deadline; polling stopped, early accessor remains',
            )
          } catch {
            // ignore
          }
        }
        return
      }
    }

    const delay = attachedServer ? options.serverIdlePollMs : options.serverPollMs
    timer = setTimeout(tick, delay)
    timer.unref?.()
  }

  tick()

  return () => {
    stopped = true
    if (timer) clearTimeout(timer)
    timer = null
    hook?.dispose()
    hook = null
    attachedServer = null
    restoreServerProperty?.()
    restoreServerProperty = null
  }
}

export function apply(ctx, config) {
  if (!ctx || typeof ctx.effect !== 'function') {
    throw new TypeError('dsh-auth-cookie-hygiene: a plugin context with effect() is required')
  }
  const options = normalizeOptions(config)
  const logger = ctx.logger
  const liveness = new PortLiveness({
    probeTimeoutMs: options.probeTimeoutMs,
    confirmGapMs: options.confirmGapMs,
    closedTtlMs: options.closedTtlMs,
    openTtlMs: options.openTtlMs,
    retryBackoffMs: options.retryBackoffMs,
    maxPorts: options.maxPorts,
  })

  if (options.debug) {
    try {
      logger?.info?.('[dsh-auth-cookie-hygiene] enabled', {
        maxPerResponse: options.maxPerResponse,
        maxExtraHeaderBytes: options.maxExtraHeaderBytes,
      })
    } catch {
      // ignore
    }
  }

  ctx.effect(() => {
    const stopWatching = watchWebServer(ctx, { options, liveness, logger })
    return () => {
      stopWatching()
      liveness.dispose()
    }
  }, 'dsh-auth-cookie-hygiene')
}

export default { name, inject, apply }