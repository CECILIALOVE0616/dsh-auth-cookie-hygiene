import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import {
  buildExpirySetCookie,
  cookieNameForAuthority,
} from '../lib/cookie.js'
import { installServerHook } from '../lib/hook.js'
import {
  close,
  listen,
  makeAuthCookie,
  request,
  setCookieName,
  setCookiesOf,
  startHookedServer,
  waitFor,
} from './helpers.js'

function fakeLiveness(statusByPort = {}) {
  return {
    status(port) {
      return statusByPort[port] ?? 'unknown'
    },
    dispose() {},
  }
}

function allClosed() {
  return { status: () => 'closed', dispose() {} }
}

async function hooked(t, options = {}) {
  const instance = await startHookedServer(options)
  t.after(async () => {
    instance.hook.dispose()
    await close(instance.server)
  })
  return instance
}

test('preserves the cookie for the current Host and leaves the response alone', async (t) => {
  const h = await hooked(t, { hookOptions: { liveness: allClosed() } })
  const cookie = makeAuthCookie(h.authority)
  const response = await request(h.server, { cookies: [cookie] })
  assert.equal(response.status, 200)
  assert.equal(response.body, 'ok')
  assert.deepEqual(setCookiesOf(response), [])
})

test('adds exactly one Max-Age=0 header for a cookie whose old Host is closed', async (t) => {
  const stalePort = 61_001
  const h = await hooked(t, {
    hookOptions: { liveness: fakeLiveness({ [stalePort]: 'closed' }) },
  })
  const stale = makeAuthCookie(`127.0.0.1:${stalePort}`)
  const response = await request(h.server, { cookies: [stale] })
  assert.equal(response.status, 200)
  assert.equal(response.body, 'ok')
  assert.deepEqual(setCookiesOf(response), [buildExpirySetCookie(stale.name)])
})

test('preserves cookies for another Host that is still listening', async (t) => {
  const activePort = 61_002
  const stalePort = 61_003
  const h = await hooked(t, {
    hookOptions: {
      liveness: fakeLiveness({ [activePort]: 'open', [stalePort]: 'closed' }),
    },
  })
  const active = makeAuthCookie(`127.0.0.1:${activePort}`)
  const stale = makeAuthCookie(`127.0.0.1:${stalePort}`)
  const response = await request(h.server, { cookies: [active, stale] })
  assert.deepEqual(setCookiesOf(response), [buildExpirySetCookie(stale.name)])
})

test('preserves v2 API cookies, remote authorities, and malformed values', async (t) => {
  const h = await hooked(t, { hookOptions: { liveness: allClosed() } })
  const remoteAuthority = '192.168.1.20:61004'
  const v2 = makeAuthCookie('127.0.0.1:61005', { version: 2 })
  const remote = makeAuthCookie(remoteAuthority)
  const injected = makeAuthCookie('127.0.0.1:61006/evil')
  const wrongHash = makeAuthCookie('127.0.0.1:61007', {
    name: cookieNameForAuthority('127.0.0.1:61008'),
  })
  const garbage = { name: cookieNameForAuthority('127.0.0.1:61009'), value: 'garbage' }
  const response = await request(h.server, {
    cookies: [v2, remote, injected, wrongHash, garbage],
  })
  assert.equal(response.status, 200)
  assert.deepEqual(setCookiesOf(response), [])
})

test('303 redirect keeps its headers, its fresh cookie, and gains the expiry', async (t) => {
  const fresh = `dsh-auth-${'B'.repeat(43)}=fresh; Path=/; HttpOnly; SameSite=Strict`
  const stalePort = 61_010
  const h = await hooked(t, {
    hookOptions: { liveness: fakeLiveness({ [stalePort]: 'closed' }) },
    handler(req, res) {
      res.writeHead(303, {
        'cache-control': 'no-store',
        location: './',
        'referrer-policy': 'no-referrer',
        'set-cookie': fresh,
      })
      res.end()
    },
  })
  const stale = makeAuthCookie(`127.0.0.1:${stalePort}`)
  const response = await request(h.server, { cookies: [stale] })
  assert.equal(response.status, 303)
  assert.equal(response.headers.location, './')
  assert.equal(response.headers['cache-control'], 'no-store')
  assert.equal(response.headers['referrer-policy'], 'no-referrer')
  const cookies = setCookiesOf(response)
  assert.equal(cookies.length, 2)
  assert.equal(cookies[0], fresh)
  assert.equal(cookies[1], buildExpirySetCookie(stale.name))
})

test('merges with a Set-Cookie installed before writeHead', async (t) => {
  const fresh = `dsh-auth-${'C'.repeat(43)}=fresh; Path=/`
  const stalePort = 61_011
  const h = await hooked(t, {
    hookOptions: { liveness: fakeLiveness({ [stalePort]: 'closed' }) },
    handler(req, res) {
      res.setHeader('Set-Cookie', fresh)
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('body')
    },
  })
  const stale = makeAuthCookie(`127.0.0.1:${stalePort}`)
  const response = await request(h.server, { cookies: [stale] })
  assert.equal(response.status, 200)
  assert.equal(response.body, 'body')
  assert.deepEqual(setCookiesOf(response), [fresh, buildExpirySetCookie(stale.name)])
})

test('writeHead(status, statusMessage, headers) still works', async (t) => {
  const stalePort = 61_012
  const h = await hooked(t, {
    hookOptions: { liveness: fakeLiveness({ [stalePort]: 'closed' }) },
    handler(req, res) {
      res.writeHead(200, 'OK', { 'content-type': 'text/plain' })
      res.end('created')
    },
  })
  const stale = makeAuthCookie(`127.0.0.1:${stalePort}`)
  const response = await request(h.server, { cookies: [stale] })
  assert.equal(response.status, 200)
  assert.equal(response.statusMessage, 'OK')
  assert.equal(response.body, 'created')
  assert.equal(setCookiesOf(response).length, 1)
})

test('writeHead(statusCode) without a headers object is supported', async (t) => {
  const stalePort = 61_013
  const h = await hooked(t, {
    hookOptions: { liveness: fakeLiveness({ [stalePort]: 'closed' }) },
    handler(req, res) {
      res.writeHead(200)
      res.end()
    },
  })
  const stale = makeAuthCookie(`127.0.0.1:${stalePort}`)
  const response = await request(h.server, { cookies: [stale] })
  assert.equal(response.status, 200)
  assert.equal(setCookiesOf(response).length, 1)
})

test('caps expiries per response and total extra header bytes', async (t) => {
  const ports = [61_014, 61_015, 61_016]
  const cookies = ports.map((port) => makeAuthCookie(`127.0.0.1:${port}`))
  const h = await hooked(t, {
    hookOptions: {
      liveness: fakeLiveness(Object.fromEntries(ports.map((port) => [port, 'closed']))),
      maxPerResponse: 2,
    },
  })
  const response = await request(h.server, { cookies })
  assert.deepEqual(
    setCookiesOf(response).map(setCookieName),
    cookies.slice(0, 2).map((cookie) => cookie.name),
  )

  const tight = await hooked(t, {
    hookOptions: {
      liveness: fakeLiveness(Object.fromEntries(ports.map((port) => [port, 'closed']))),
      maxExtraHeaderBytes: 256,
    },
  })
  const tightResponse = await request(tight.server, { cookies })
  assert.equal(setCookiesOf(tightResponse).length, 1)
})

test('does not resend the same expiry within the recent TTL', async (t) => {
  const portA = 61_017
  const portB = 61_018
  const h = await hooked(t, {
    hookOptions: { liveness: fakeLiveness({ [portA]: 'closed', [portB]: 'closed' }) },
  })
  const a = makeAuthCookie(`127.0.0.1:${portA}`)
  const b = makeAuthCookie(`127.0.0.1:${portB}`)

  const first = await request(h.server, { cookies: [a] })
  assert.equal(setCookiesOf(first).length, 1)
  const second = await request(h.server, { cookies: [a] })
  assert.equal(setCookiesOf(second).length, 0)
  const third = await request(h.server, { cookies: [a, b] })
  assert.deepEqual(setCookiesOf(third), [buildExpirySetCookie(b.name)])
})

test('enabled: false installs the hook but never emits an expiry', async (t) => {
  const h = await startHookedServer({
    hookOptions: { enabled: false, liveness: allClosed() },
  })
  t.after(() => close(h.server))
  const stale = makeAuthCookie('127.0.0.1:61_021')
  const response = await request(h.server, { cookies: [stale] })
  assert.equal(response.status, 200)
  assert.deepEqual(setCookiesOf(response), [])
})

test('installing twice is idempotent and dispose removes the listener', async (t) => {
  const server = await listen()
  t.after(() => close(server))
  const baseline = server.listenerCount('request')
  const options = { liveness: fakeLiveness({ 61_019: 'closed' }) }
  const first = installServerHook(server, options)
  const second = installServerHook(server, options)
  assert.equal(first, second)
  assert.equal(server.listenerCount('request'), baseline + 1)

  first.dispose()
  first.dispose()
  assert.equal(server.listenerCount('request'), baseline)

  const stale = makeAuthCookie('127.0.0.1:61_019')
  const response = await request(server, { cookies: [stale] })
  assert.equal(response.status, 200)
  assert.deepEqual(setCookiesOf(response), [])
})

test('a failing liveness check or malformed header never breaks the response', async (t) => {
  const h = await hooked(t, {
    hookOptions: {
      liveness: {
        status() {
          throw new Error('probe exploded')
        },
      },
    },
  })
  const stale = makeAuthCookie('127.0.0.1:61_020')
  const response = await request(h.server, {
    cookies: [stale],
    headers: { cookie: `;;;=; ${stale.name}=${stale.value}; bad` },
  })
  assert.equal(response.status, 200)
  assert.equal(response.body, 'ok')
  assert.deepEqual(setCookiesOf(response), [])

  const after = await request(h.server)
  assert.equal(after.status, 200)
})

test('HEAD responses get the expiry; POST is not touched', async (t) => {
  const stalePort = 61_021
  const h = await hooked(t, {
    hookOptions: { liveness: fakeLiveness({ [stalePort]: 'closed' }) },
  })
  const stale = makeAuthCookie(`127.0.0.1:${stalePort}`)
  const head = await request(h.server, { method: 'HEAD', cookies: [stale] })
  assert.equal(head.status, 200)
  assert.equal(head.body, '')
  assert.equal(setCookiesOf(head).length, 1)

  const post = await request(h.server, { method: 'POST', cookies: [stale] })
  assert.equal(post.status, 200)
  assert.deepEqual(setCookiesOf(post), [])
})

test('a simulated jar stays bounded across repeated page loads', async (t) => {
  const ports = Array.from({ length: 20 }, (_, index) => 61_100 + index)
  const h = await hooked(t, {
    hookOptions: {
      liveness: fakeLiveness(Object.fromEntries(ports.map((port) => [port, 'closed']))),
      maxPerResponse: 8,
    },
  })
  const current = makeAuthCookie(h.authority)
  const jar = new Map([[current.name, current.value]])
  for (const port of ports) {
    const cookie = makeAuthCookie(`127.0.0.1:${port}`)
    jar.set(cookie.name, cookie.value)
  }

  for (let round = 0; round < 5 && jar.size > 1; round += 1) {
    const cookies = [...jar].map(([name, value]) => ({ name, value }))
    const response = await request(h.server, { cookies })
    const expiries = setCookiesOf(response).map(setCookieName)
    assert.ok(expiries.length <= 8)
    for (const name of expiries) jar.delete(name)
  }

  assert.equal(jar.size, 1)
  assert.ok(jar.has(current.name))
})

test('real TCP liveness cleans a cookie whose old Host is really gone', async (t) => {
  const dead = net.createServer()
  await new Promise((resolve, reject) => {
    dead.once('error', reject)
    dead.listen(0, '127.0.0.1', resolve)
  })
  const { port: deadPort } = dead.address()
  await close(dead)

  const h = await hooked(t, {
    hookOptions: {
      probeTimeoutMs: 100,
      confirmGapMs: 20,
      retryBackoffMs: 50,
    },
  })
  const stale = makeAuthCookie(`127.0.0.1:${deadPort}`)

  await waitFor(
    async () => {
      const response = await request(h.server, { cookies: [stale] })
      return setCookiesOf(response).length === 1
    },
    { timeout: 4000, interval: 30, label: 'real cleanup header' },
  )
})

test('repeated cold restarts keep a browser jar bounded without prewarming or waits', async (t) => {
  const jar = new Map()
  const authorities = []

  for (let i = 0; i < 12; i += 1) {
    const h = await startHookedServer({
      handler(req, res) {
        const current = makeAuthCookie(req.headers.host)
        res.writeHead(303, {
          location: './',
          'cache-control': 'no-store',
          'set-cookie': `${current.name}=${current.value}; Path=/; HttpOnly; SameSite=Strict`,
        })
        res.end()
      },
    })
    authorities.push(h.authority)

    const cookies = [...jar].map(([name, value]) => ({ name, value }))
    const response = await request(h.server, { cookies })
    assert.equal(response.status, 303)

    for (const setCookie of setCookiesOf(response)) {
      const eq = setCookie.indexOf('=')
      const name = setCookie.slice(0, eq)
      if (/Max-Age=0/i.test(setCookie) || /Expires=Thu, 01 Jan 1970/i.test(setCookie)) {
        jar.delete(name)
        continue
      }
      const semi = setCookie.indexOf(';')
      jar.set(name, setCookie.slice(eq + 1, semi === -1 ? undefined : semi))
    }

    h.hook.dispose()
    await close(h.server)
  }

  const last = authorities.at(-1)
  assert.equal(jar.size, 1)
  assert.ok(jar.has(cookieNameForAuthority(last)))
  for (const authority of authorities.slice(0, -1)) {
    assert.ok(!jar.has(cookieNameForAuthority(authority)))
  }
})
