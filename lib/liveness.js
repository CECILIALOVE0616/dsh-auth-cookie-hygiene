import net from 'node:net'

const DEFAULT_OPTIONS = Object.freeze({
  probeTimeoutMs: 250,
  confirmGapMs: 120,
  closedTtlMs: 30_000,
  openTtlMs: 15_000,
  retryBackoffMs: 2_000,
  maxPorts: 256,
})

function toInt(value, fallback, min, max) {
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback
}

/**
 * Lightweight loopback port liveness cache.
 *
 * - Only 127.0.0.1 is ever connected to; no DNS, no other address families.
 * - At most one probe per port is in flight.
 * - A port becomes `closed` only after two ECONNREFUSED observations at least
 *   `confirmGapMs` apart. Timeouts, resets and other errors leave it `unknown`,
 *   which callers treat conservatively (keep the cookie).
 * - `closed` is re-checked after `closedTtlMs`; an expired entry never stays
 *   `closed` without a new confirmation.
 */
export class PortLiveness {
  constructor(options = {}) {
    this.probeTimeoutMs = toInt(options.probeTimeoutMs, DEFAULT_OPTIONS.probeTimeoutMs, 20, 5000)
    this.confirmGapMs = toInt(options.confirmGapMs, DEFAULT_OPTIONS.confirmGapMs, 0, 60_000)
    this.closedTtlMs = toInt(options.closedTtlMs, DEFAULT_OPTIONS.closedTtlMs, 100, 10 * 60_000)
    this.openTtlMs = toInt(options.openTtlMs, DEFAULT_OPTIONS.openTtlMs, 100, 10 * 60_000)
    this.retryBackoffMs = toInt(options.retryBackoffMs, DEFAULT_OPTIONS.retryBackoffMs, 50, 60_000)
    this.maxPorts = toInt(options.maxPorts, DEFAULT_OPTIONS.maxPorts, 1, 4096)
    this._connect =
      typeof options.connect === 'function' ? options.connect : (opts) => net.connect(opts)
    this._now = typeof options.now === 'function' ? options.now : Date.now
    this._states = new Map()
    this._sockets = new Set()
    this._timers = new Set()
    this._fresh = new Map()
    this._disposed = false
  }

  /** @returns {'open'|'closed'|'unknown'} */
  status(port) {
    if (this._disposed || !Number.isInteger(port) || port < 1 || port > 65535) return 'unknown'
    const now = this._now()
    let entry = this._states.get(port)
    if (!entry) {
      // Hard bound: once the table is full, probe status for new ports is
      // unknown until an existing entry is evicted. Never grow past maxPorts.
      if (this._states.size >= this.maxPorts) return 'unknown'
      entry = {
        status: 'unknown',
        at: 0,
        inFlight: false,
        lastClosedAt: 0,
        nextProbeAt: 0,
        touchedAt: now,
      }
      this._states.set(port, entry)
      this._evict()
      this._start(port, entry)
      return 'unknown'
    }

    entry.touchedAt = now
    if (entry.inFlight) return 'unknown'
    const age = now - entry.at
    if (entry.status === 'open' && age <= this.openTtlMs) return 'open'
    if (entry.status === 'closed' && age <= this.closedTtlMs) return 'closed'
    if (now >= entry.nextProbeAt) this._start(port, entry)
    return 'unknown'
  }

  /**
   * Fresh, bounded confirmation used for a single response decision.
   *
   * Unlike `status()`, this ignores the cache: it connects now, waits for a
   * second ECONNREFUSED observation when needed, and resolves `closed` only for
   * two refusals at least `confirmGapMs` apart. Any timeout or other error is
   * `unknown`. At most one sequence runs per port; concurrent callers share it.
   *
   * @param {number} port
   * @param {{timeoutMs?: number}} [options]
   * @returns {Promise<'open'|'closed'|'unknown'>}
   */
  confirmFresh(port, { timeoutMs = 700 } = {}) {
    if (this._disposed || !Number.isInteger(port) || port < 1 || port > 65535) {
      return Promise.resolve('unknown')
    }
    const existing = this._fresh.get(port)
    if (existing) return existing.promise
    if (this._fresh.size >= this.maxPorts) return Promise.resolve('unknown')

    let resolvePromise
    const promise = new Promise((resolve) => {
      resolvePromise = resolve
    })

    const record = { done: false, timer: null, gapTimer: null, finish: null }
    const finish = (value) => {
      if (record.done) return
      record.done = true
      if (record.timer) {
        clearTimeout(record.timer)
        this._timers.delete(record.timer)
      }
      if (record.gapTimer) {
        clearTimeout(record.gapTimer)
        this._timers.delete(record.gapTimer)
      }
      this._fresh.delete(port)
      resolvePromise(value)
    }
    record.finish = finish

    record.timer = setTimeout(() => finish('unknown'), toInt(timeoutMs, 700, 100, 5000))
    record.timer.unref?.()
    this._timers.add(record.timer)
    this._fresh.set(port, { promise, cancel: () => finish('unknown') })

    this._probeOnce(port).then(
      (first) => {
        if (record.done) return
        if (first === 'open') {
          finish('open')
          return
        }
        if (first !== 'refused') {
          finish('unknown')
          return
        }
        record.gapTimer = setTimeout(() => {
          this._timers.delete(record.gapTimer)
          if (record.done) return
          this._probeOnce(port).then(
            (second) => {
              if (record.done) return
              if (second === 'refused') finish('closed')
              else if (second === 'open') finish('open')
              else finish('unknown')
            },
            () => finish('unknown'),
          )
        }, this.confirmGapMs)
        record.gapTimer.unref?.()
        this._timers.add(record.gapTimer)
      },
      () => finish('unknown'),
    )

    return promise
  }

  _probeOnce(port) {
    return new Promise((resolve) => {
      let socket
      let timer = null
      let settled = false
      const done = (result) => {
        if (settled) return
        settled = true
        if (timer) {
          clearTimeout(timer)
          this._timers.delete(timer)
        }
        this._sockets.delete(socket)
        try {
          socket?.destroy?.()
        } catch {
          // ignore teardown errors
        }
        resolve(result)
      }

      try {
        socket = this._connect({ host: '127.0.0.1', port, family: 4 })
      } catch {
        done('unknown')
        return
      }
      if (!socket || typeof socket.once !== 'function') {
        done('unknown')
        return
      }

      this._sockets.add(socket)
      timer = setTimeout(() => done('unknown'), this.probeTimeoutMs)
      timer.unref?.()
      this._timers.add(timer)

      try {
        socket.setTimeout?.(this.probeTimeoutMs)
        socket.unref?.()
        socket.once('connect', () => done('open'))
        socket.once('error', (error) =>
          done(error && error.code === 'ECONNREFUSED' ? 'refused' : 'unknown'),
        )
        socket.once('close', () => done('unknown'))
      } catch {
        done('unknown')
      }
    })
  }

  _start(port, entry) {
    if (this._disposed || entry.inFlight || this._states.get(port) !== entry) return
    entry.inFlight = true

    let socket
    try {
      socket = this._connect({ host: '127.0.0.1', port, family: 4 })
    } catch {
      entry.inFlight = false
      this._settle(port, entry, 'unknown')
      return
    }
    if (!socket || typeof socket.once !== 'function') {
      entry.inFlight = false
      this._settle(port, entry, 'unknown')
      return
    }

    this._sockets.add(socket)
    let settled = false
    const finish = (kind) => {
      if (settled) return
      settled = true
      entry.inFlight = false
      this._sockets.delete(socket)
      try {
        socket.destroy?.()
      } catch {
        // ignore teardown errors
      }
      if (!this._disposed) this._settle(port, entry, kind)
    }

    try {
      socket.setTimeout?.(this.probeTimeoutMs)
      socket.unref?.()
      socket.once('connect', () => finish('open'))
      socket.once('timeout', () => finish('unknown'))
      socket.once('error', (error) =>
        finish(error && error.code === 'ECONNREFUSED' ? 'closed' : 'unknown'),
      )
      socket.once('close', () => finish('unknown'))
    } catch {
      finish('unknown')
    }
  }

  _settle(port, entry, kind) {
    if (this._states.get(port) !== entry) return
    const now = this._now()
    if (kind === 'open') {
      entry.status = 'open'
      entry.at = now
      entry.lastClosedAt = 0
      entry.nextProbeAt = 0
      return
    }
    if (kind === 'closed') {
      const anchor = entry.lastClosedAt
      if (anchor > 0 && now - anchor >= this.confirmGapMs) {
        entry.status = 'closed'
        entry.at = now
        entry.lastClosedAt = now
        entry.nextProbeAt = 0
      } else {
        // Keep the first refusal as the anchor and retry exactly one gap later.
        // Updating the anchor on an early timer could postpone the second
        // observation indefinitely.
        if (anchor === 0) entry.lastClosedAt = now
        entry.status = 'unknown'
        entry.at = now
        entry.nextProbeAt = (anchor || now) + this.confirmGapMs
        this._schedule(port, entry, Math.max(1, entry.nextProbeAt - now))
      }
      return
    }
    entry.status = 'unknown'
    entry.at = now
    entry.nextProbeAt = now + this.retryBackoffMs
  }

  _schedule(port, entry, delay) {
    if (this._disposed) return
    const timer = setTimeout(() => {
      this._timers.delete(timer)
      if (!this._disposed) this._start(port, entry)
    }, Math.max(1, delay))
    timer.unref?.()
    this._timers.add(timer)
  }

  _evict() {
    while (this._states.size > this.maxPorts) {
      let removed = false
      for (const [port, entry] of this._states) {
        if (entry.inFlight) continue
        this._states.delete(port)
        removed = true
        break
      }
      if (!removed) break
    }
  }

  dispose() {
    this._disposed = true
    const fresh = [...this._fresh.values()]
    this._fresh.clear()
    for (const record of fresh) {
      try {
        record.cancel()
      } catch {
        // ignore
      }
    }
    for (const timer of this._timers) clearTimeout(timer)
    this._timers.clear()
    for (const socket of this._sockets) {
      try {
        socket.destroy?.()
      } catch {
        // ignore
      }
    }
    this._sockets.clear()
    this._states.clear()
  }
}

export const livenessDefaults = DEFAULT_OPTIONS
