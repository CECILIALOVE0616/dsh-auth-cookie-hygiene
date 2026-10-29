import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { EventEmitter } from 'node:events'
import { PortLiveness } from '../lib/liveness.js'
import { close, delay, waitFor } from './helpers.js'

function fakeSocket(event, error) {
  const socket = new EventEmitter()
  socket.destroyed = false
  socket.setTimeout = () => {}
  socket.unref = () => {}
  socket.destroy = () => {
    socket.destroyed = true
  }
  process.nextTick(() => {
    if (error) socket.emit('error', error)
    else socket.emit(event)
  })
  return socket
}

function refused() {
  return Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })
}

test('an accepting socket becomes open without a confirmation delay', async () => {
  let calls = 0
  const liveness = new PortLiveness({
    connect: () => {
      calls += 1
      return fakeSocket('connect')
    },
  })
  assert.equal(liveness.status(5000), 'unknown')
  await waitFor(() => liveness.status(5000) === 'open', { label: 'open' })
  assert.equal(calls, 1)
  liveness.dispose()
})

test('a refused port needs two observations separated by confirmGapMs', async () => {
  let calls = 0
  const liveness = new PortLiveness({
    connect: () => {
      calls += 1
      return fakeSocket('error', refused())
    },
    confirmGapMs: 20,
  })
  assert.equal(liveness.status(5000), 'unknown')
  await waitFor(() => calls >= 2, { timeout: 1000, label: 'second probe' })
  await waitFor(() => liveness.status(5000) === 'closed', { label: 'closed' })
  assert.ok(calls >= 2)
  liveness.dispose()
})

test('timeouts and non-refused errors stay unknown and do not expire cookies', async () => {
  let calls = 0
  const liveness = new PortLiveness({
    connect: () => {
      calls += 1
      return fakeSocket('timeout')
    },
    retryBackoffMs: 10_000,
  })
  assert.equal(liveness.status(5000), 'unknown')
  await delay(60)
  assert.equal(liveness.status(5000), 'unknown')
  assert.equal(calls, 1)
  assert.equal(liveness.status(5001), 'unknown')
  await delay(30)
  assert.equal(liveness.status(5001), 'unknown')
  liveness.dispose()
})

test('at most one probe per port is in flight', async () => {
  let calls = 0
  let release
  const gate = new Promise((resolve) => {
    release = resolve
  })
  const liveness = new PortLiveness({
    connect: () => {
      calls += 1
      const socket = new EventEmitter()
      socket.setTimeout = () => {}
      socket.unref = () => {}
      socket.destroy = () => {}
      gate.then(() => socket.emit('connect'))
      return socket
    },
  })
  for (let i = 0; i < 10; i += 1) liveness.status(5000)
  assert.equal(calls, 1)
  release()
  await waitFor(() => liveness.status(5000) === 'open', { label: 'open' })
  liveness.dispose()
})

test('expired open state is re-probed instead of being trusted forever', async () => {
  let clock = 1_000_000
  let calls = 0
  const liveness = new PortLiveness({
    now: () => clock,
    openTtlMs: 100,
    connect: () => {
      calls += 1
      return fakeSocket('connect')
    },
  })
  liveness.status(5000)
  await waitFor(() => liveness.status(5000) === 'open', { label: 'initial open' })
  clock += 101
  assert.equal(liveness.status(5000), 'unknown')
  await waitFor(() => liveness.status(5000) === 'open', { label: 'refreshed open' })
  assert.equal(calls, 2)
  liveness.dispose()
})

test('dispose tears down sockets and stops future probes', async () => {
  const socket = new EventEmitter()
  socket.setTimeout = () => {}
  socket.unref = () => {}
  socket.destroyed = false
  socket.destroy = () => {
    socket.destroyed = true
  }
  let calls = 0
  const liveness = new PortLiveness({
    connect: () => {
      calls += 1
      return socket
    },
  })
  liveness.status(5000)
  liveness.dispose()
  assert.equal(socket.destroyed, true)
  assert.equal(liveness.status(5000), 'unknown')
  assert.equal(calls, 1)
})

test('invalid ports never open a socket', () => {
  let calls = 0
  const liveness = new PortLiveness({
    connect: () => {
      calls += 1
      return fakeSocket('connect')
    },
  })
  for (const port of [0, -1, 65536, 1.5, NaN, '5000']) {
    assert.equal(liveness.status(port), 'unknown')
  }
  assert.equal(calls, 0)
  liveness.dispose()
})

test('state map is bounded by maxPorts', async () => {
  const liveness = new PortLiveness({
    maxPorts: 2,
    connect: () => fakeSocket('connect'),
  })
  for (let port = 5000; port < 5010; port += 1) liveness.status(port)
  await delay(30)
  liveness.status(5010)
  await delay(30)
  assert.ok(liveness._states.size <= 2, `states=${liveness._states.size}`)
  liveness.dispose()
})

test('real loopback probe detects an open server and then a closed one', async () => {
  const server = net.createServer((socket) => socket.end())
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const { port } = server.address()
  try {
    const openLiveness = new PortLiveness({ probeTimeoutMs: 100 })
    await waitFor(() => openLiveness.status(port) === 'open', { label: 'real open' })
    openLiveness.dispose()

    await close(server)
    const closedLiveness = new PortLiveness({
      probeTimeoutMs: 100,
      confirmGapMs: 10,
      retryBackoffMs: 50,
    })
    try {
      await waitFor(() => closedLiveness.status(port) === 'closed', {
        timeout: 3000,
        label: 'real closed',
      })
    } finally {
      closedLiveness.dispose()
    }
  } finally {
    await close(server)
  }
})

test('localhost is not probed through DNS (only literal 127.0.0.1 is passed)', async () => {
  const hosts = []
  const liveness = new PortLiveness({
    connect: (options) => {
      hosts.push(options.host)
      return fakeSocket('connect')
    },
  })
  liveness.status(5000)
  await waitFor(() => liveness.status(5000) === 'open')
  assert.deepEqual(hosts, ['127.0.0.1'])
  liveness.dispose()
})
