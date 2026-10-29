import test from 'node:test'
import assert from 'node:assert/strict'
import { apply, normalizeOptions } from '../lib/index.js'
import { close, delay, listen, request, setCookiesOf, waitFor } from './helpers.js'

function fakeContext(webServer) {
  const disposers = []
  return {
    webServer,
    logger: { info() {}, warn() {} },
    effect(fn) {
      const dispose = fn()
      if (typeof dispose === 'function') disposers.push(dispose)
      return dispose
    },
    async dispose() {
      while (disposers.length > 0) await disposers.pop()()
    },
  }
}

test('normalizeOptions applies defaults and clamps invalid values', () => {
  const defaults = normalizeOptions({})
  assert.equal(defaults.maxPerResponse, 8)
  assert.equal(defaults.maxExtraHeaderBytes, 3072)
  assert.equal(defaults.serverPollMs, 50)
  assert.equal(defaults.enabled, true)
  assert.equal(defaults.maxPorts, 256)
  assert.equal(defaults.maxRecent, 512)
  assert.equal(normalizeOptions({ enabled: false }).enabled, false)
  assert.equal(normalizeOptions({ maxPorts: 9999 }).maxPorts, 256)
  assert.equal(normalizeOptions({ maxRecent: 4 }).maxRecent, 512)
  assert.equal(normalizeOptions({ maxPerResponse: 999 }).maxPerResponse, 8)
  assert.equal(normalizeOptions({ maxPerResponse: 3 }).maxPerResponse, 3)
  assert.equal(normalizeOptions({ serverPollMs: 1 }).serverPollMs, 50)
  assert.equal(normalizeOptions(null).maxCandidatesPerRequest, 64)
})

test('apply waits for webServer.server, attaches once, and detaches on dispose', async (t) => {
  const webServer = { server: null, protocol: 'http:' }
  const ctx = fakeContext(webServer)
  let server
  let attached = false
  t.after(async () => {
    await ctx.dispose()
    if (server) await close(server)
  })

  apply(ctx, { serverPollMs: 10, serverIdlePollMs: 20, serverDeadlineMs: 2000 })
  await delay(30)
  assert.equal(attached, false)

  server = await listen()
  webServer.server = server
  await waitFor(() => server.listenerCount('request') > 1, { label: 'hook attached' })
  attached = true
  assert.equal(server.listenerCount('request'), 2)

  const response = await request(server)
  assert.equal(response.status, 200)
  assert.equal(response.body, 'ok')
  assert.deepEqual(setCookiesOf(response), [])

  await ctx.dispose()
  assert.equal(server.listenerCount('request'), 1)
})

test('server swaps move the hook without stacking listeners', async (t) => {
  const first = await listen()
  const second = await listen()
  const webServer = { server: first, protocol: 'http:' }
  const ctx = fakeContext(webServer)
  t.after(async () => {
    await ctx.dispose()
    await close(first)
    await close(second)
  })

  apply(ctx, { serverPollMs: 10, serverIdlePollMs: 20, serverDeadlineMs: 2000 })
  await waitFor(() => first.listenerCount('request') === 2, { label: 'first attach' })
  webServer.server = second
  await waitFor(() => second.listenerCount('request') === 2, { label: 'second attach' })
  assert.equal(first.listenerCount('request'), 1)
  assert.equal(second.listenerCount('request'), 2)

  await ctx.dispose()
  assert.equal(second.listenerCount('request'), 1)
})

test('dispose before the server appears leaves no timer or listener behind', async (t) => {
  const webServer = { server: null, protocol: 'http:' }
  const ctx = fakeContext(webServer)
  let server
  t.after(async () => {
    if (server) await close(server)
  })

  apply(ctx, { serverPollMs: 10, serverIdlePollMs: 20, serverDeadlineMs: 2000 })
  await ctx.dispose()
  server = await listen()
  webServer.server = server
  await delay(60)
  assert.equal(server.listenerCount('request'), 1)
})

test('early server accessor attaches at assignment even after the polling deadline', async (t) => {
  const webServer = { server: null, protocol: 'http:' }
  const ctx = fakeContext(webServer)
  let server
  t.after(async () => {
    await ctx.dispose()
    if (server) await close(server)
  })

  apply(ctx, { serverPollMs: 10, serverDeadlineMs: 30 })
  await delay(100)
  server = await listen()
  webServer.server = server
  await delay(60)
  assert.equal(server.listenerCount('request'), 2)
})
