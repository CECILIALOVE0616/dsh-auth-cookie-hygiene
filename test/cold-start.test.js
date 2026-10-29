import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { EventEmitter } from 'node:events'
import { installServerHook } from '../lib/hook.js'
import { PortLiveness } from '../lib/liveness.js'
import { close, delay, listen, makeAuthCookie, request, setCookiesOf } from './helpers.js'

const pending = () => ({ status: () => 'unknown', confirmFresh: () => new Promise(() => {}) })
const closed = () => ({ status: () => 'closed', confirmFresh: async () => 'closed' })

test('first cold request expires a genuinely closed port, without prewarming', async (t) => {
  const old = createServer()
  await new Promise(r => old.listen(0, '127.0.0.1', r))
  const port = old.address().port
  await new Promise(r => old.close(r))
  const server = await listen()
  const hook = installServerHook(server)
  t.after(async () => { hook.dispose(); await close(server) })
  const response = await request(server, { cookies: [makeAuthCookie(`127.0.0.1:${port}`)] })
  assert.equal(response.status, 200)
  assert.equal(setCookiesOf(response).length, 1)
})

test('uninstall flushes a response already ended while confirmation is pending', async (t) => {
  let started
  const entered = new Promise(r => { started = r })
  const server = await listen((req, res) => { res.writeHead(303, { location: './' }); res.end('done'); started() })
  const hook = installServerHook(server, { liveness: pending() })
  t.after(async () => { hook.dispose(); await close(server) })
  const response = request(server, { cookies: [makeAuthCookie('127.0.0.1:61001')] })
  await entered
  hook.dispose()
  const result = await response
  assert.equal(result.status, 303)
  assert.equal(result.headers.location, './')
  assert.equal(result.body, 'done')
  assert.deepEqual(setCookiesOf(result), [])
})

test('implicit unauthorized response is not promoted to 200 or delayed', async (t) => {
  const server = await listen((req, res) => { res.statusCode = 401; res.end('unauthorized') })
  const hook = installServerHook(server, { liveness: pending() })
  t.after(async () => { hook.dispose(); await close(server) })
  const result = await request(server, { cookies: [makeAuthCookie('127.0.0.1:61002')] })
  assert.equal(result.status, 401)
  assert.equal(result.body, 'unauthorized')
  assert.deepEqual(setCookiesOf(result), [])
})

test('explicit unauthorized and unrelated created responses remain unchanged', async (t) => {
  for (const code of [401, 403, 201]) {
    const server = await listen((req, res) => { res.writeHead(code, { 'x-test': 'keep' }); res.end('same') })
    const hook = installServerHook(server, { liveness: closed() })
    try {
      const result = await request(server, { cookies: [makeAuthCookie('127.0.0.1:61003')] })
      assert.equal(result.status, code)
      assert.equal(result.body, 'same')
      assert.equal(result.headers['x-test'], 'keep')
      assert.deepEqual(setCookiesOf(result), [])
    } finally { hook.dispose(); await close(server) }
  }
})

test('streaming writes are forwarded immediately without buffering or expiry', async (t) => {
  const server = await listen((req, res) => { res.writeHead(200); res.write('first'); res.end('last') })
  const hook = installServerHook(server, { liveness: pending() })
  t.after(async () => { hook.dispose(); await close(server) })
  const result = await request(server, { cookies: [makeAuthCookie('127.0.0.1:61004')] })
  assert.equal(result.body, 'firstlast')
  assert.deepEqual(setCookiesOf(result), [])
})

test('flushHeaders forwards headers and subsequent body without waiting', async (t) => {
  const server = await listen((req, res) => { res.writeHead(200); res.flushHeaders(); res.end('flushed') })
  const hook = installServerHook(server, { liveness: pending() })
  t.after(async () => { hook.dispose(); await close(server) })
  const result = await request(server, { cookies: [makeAuthCookie('127.0.0.1:61005')] })
  assert.equal(result.body, 'flushed')
  assert.deepEqual(setCookiesOf(result), [])
})

test('unknown confirmation is bounded and fails open without changing login', async (t) => {
  const server = await listen((req, res) => { res.writeHead(303, { location: './', 'set-cookie': 'fresh=keep' }); res.end() })
  const hook = installServerHook(server, { liveness: pending(), confirmTimeoutMs: 100 })
  t.after(async () => { hook.dispose(); await close(server) })
  const result = await request(server, { cookies: [makeAuthCookie('127.0.0.1:61006')] })
  assert.equal(result.status, 303)
  assert.deepEqual(setCookiesOf(result), ['fresh=keep'])
})

test('remote or mismatched Host and non-index paths do not trigger probes', async (t) => {
  let probes = 0
  const server = await listen()
  const hook = installServerHook(server, { liveness: { status: () => { probes++; return 'closed' } } })
  t.after(async () => { hook.dispose(); await close(server) })
  for (const options of [{headers:{host:'example.com:80'}},{headers:{host:'127.0.0.1:1'}},{path:'/api/session/create'}]) {
    const result = await request(server, {...options,cookies:[makeAuthCookie('127.0.0.1:61007')]})
    assert.deepEqual(setCookiesOf(result), [])
  }
  assert.equal(probes, 0)
})

test('fresh confirmation ignores stale closed cache after a port is reused', async (t) => {
  const live = createServer(s => s.end())
  await new Promise(r => live.listen(0, '127.0.0.1', r))
  t.after(() => new Promise(r => live.close(r)))
  const port = live.address().port
  const liveness = new PortLiveness()
  t.after(() => liveness.dispose())
  liveness._states.set(port, {status:'closed',at:Date.now(),inFlight:false})
  assert.equal(liveness.status(port), 'closed')
  assert.equal(await liveness.confirmFresh(port), 'open')
})

test('a partially unwritable response is restored after hook installation failure', () => {
  const server = new EventEmitter()
  const original = () => {}
  const response = { writeHead: original, end() {}, getHeader() {}, setHeader() {} }
  Object.defineProperty(response, 'write', {value: original, writable: false})
  const hook = installServerHook(server, {liveness:closed()})
  server.emit('request', {method:'GET',url:'/',headers:{host:'127.0.0.1:12345',cookie:makeAuthCookie('127.0.0.1:61008').name+'='+makeAuthCookie('127.0.0.1:61008').value}}, response)
  assert.equal(response.writeHead, original)
  hook.dispose()
})
