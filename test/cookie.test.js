import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  buildExpirySetCookie,
  classifyBrowserAuthCookie,
  collectCookiePairs,
  cookieNameForAuthority,
  decodeBase64UrlStrict,
  encodeBase64Url,
  mergeSetCookieHeaders,
  setCookieBytes,
} from '../lib/cookie.js'
import { makeAuthCookie } from './helpers.js'

test('cookie name is dsh-auth- plus base64url sha256 of the authority', () => {
  const authority = '127.0.0.1:53421'
  const expected =
    'dsh-auth-' +
    createHash('sha256')
      .update(authority)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/u, '')
  assert.equal(cookieNameForAuthority(authority), expected)
  assert.match(cookieNameForAuthority(authority), /^dsh-auth-[A-Za-z0-9_-]{43}$/)
})

test('base64url strict decoding rejects padding and standard base64 characters', () => {
  assert.equal(decodeBase64UrlStrict('abc')?.toString('hex'), '69b7')
  assert.equal(decodeBase64UrlStrict('abc='), null)
  assert.equal(decodeBase64UrlStrict('a+b'), null)
  assert.equal(decodeBase64UrlStrict('a/b'), null)
  assert.equal(decodeBase64UrlStrict('a'), null)
  assert.equal(decodeBase64UrlStrict('')?.length, 0)
})

test('collectCookiePairs handles quoting, malformed segments, and limits', () => {
  assert.deepEqual(collectCookiePairs('a=1; b="two"; ; bad; =x; c='), [
    { name: 'a', value: '1' },
    { name: 'b', value: 'two' },
    { name: 'c', value: '' },
  ])
  assert.deepEqual(collectCookiePairs('a=' + 'x'.repeat(50), { maxBytes: 10 }), [
    { name: 'a', value: 'xxxxxxxx' },
  ])
  assert.equal(collectCookiePairs('a=1; b=2; c=3', { maxPairs: 2 }).length, 2)
  assert.deepEqual(collectCookiePairs(undefined), [])
})

test('classify accepts a self-consistent v1 cookie for 127.0.0.1', () => {
  const cookie = makeAuthCookie('127.0.0.1:53421')
  const result = classifyBrowserAuthCookie(cookie.name, cookie.value)
  assert.ok(result)
  assert.equal(result.authority, '127.0.0.1:53421')
  assert.equal(result.port, 53421)
})

test('classify keeps v2/API, non-loopback, mismatched, and malformed cookies', () => {
  const authority = '127.0.0.1:53421'
  const name = cookieNameForAuthority(authority)
  const valid = makeAuthCookie(authority)

  const cases = {
    'v2 value': makeAuthCookie(authority, { version: 2 }).value,
    'payload version 2': makeAuthCookie(authority, { payload: { version: 2 } }).value,
    localhost: makeAuthCookie('localhost:53421', { name }).value,
    'ipv6 loopback': makeAuthCookie('[::1]:53421', { name }).value,
    'other 127/8': makeAuthCookie('127.0.0.2:53421', { name }).value,
    'remote ip': makeAuthCookie('192.168.1.2:53421', { name }).value,
    'domain name': makeAuthCookie('example.com:53421', { name }).value,
    'no port': makeAuthCookie('127.0.0.1', { name }).value,
    'port zero': makeAuthCookie('127.0.0.1:0', { name }).value,
    'port too large': makeAuthCookie('127.0.0.1:65536', { name }).value,
    'leading zero port': makeAuthCookie('127.0.0.1:08080', { name }).value,
    'wrong name': makeAuthCookie('127.0.0.1:53422').value,
    'garbage value': 'garbage',
    'too many parts': `v1.${valid.value.split('.')[1]}.x.y`,
    'bad signature length': makeAuthCookie(authority, { signature: 'A'.repeat(42) }).value,
    'bad signature chars': makeAuthCookie(authority, { signature: 'A'.repeat(42) + '+' }).value,
    'expires before issued': makeAuthCookie(authority, { issuedAt: 2, expiresAt: 1 }).value,
    'unsafe issuedAt': makeAuthCookie(authority, { issuedAt: 1.5 }).value,
    'missing issuedAt': `v1.${encodeBase64Url(
      Buffer.from(JSON.stringify({ version: 1, authority, expiresAt: Date.now() + 1000 })),
    )}.${'A'.repeat(43)}`,
    'oversized body': `v1.${'A'.repeat(2500)}.${'A'.repeat(43)}`,
    'array JSON': `v1.${encodeBase64Url(Buffer.from('[]'))}.${'A'.repeat(43)}`,
  }

  for (const [label, value] of Object.entries(cases)) {
    assert.equal(classifyBrowserAuthCookie(name, value), null, label)
  }
  assert.equal(classifyBrowserAuthCookie('dsh-auth-short', valid.value), null)
  assert.equal(classifyBrowserAuthCookie(name, undefined), null)
})

test('classify rejects a name that does not hash the claimed authority', () => {
  const authority = '127.0.0.1:53421'
  const otherName = cookieNameForAuthority('127.0.0.1:53422')
  const cookie = makeAuthCookie(authority, { name: otherName })
  assert.equal(classifyBrowserAuthCookie(cookie.name, cookie.value), null)
})

test('expiry Set-Cookie has fixed attributes and optional Secure', () => {
  const name = cookieNameForAuthority('127.0.0.1:53421')
  assert.equal(
    buildExpirySetCookie(name),
    `${name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict`,
  )
  assert.equal(
    buildExpirySetCookie(name, { secure: true }).endsWith('; Secure'),
    true,
  )
  assert.throws(() => buildExpirySetCookie('not-a-cookie'), TypeError)
})

test('mergeSetCookieHeaders preserves order and strips exact duplicates', () => {
  const a = 'a=; Max-Age=0'
  const b = 'b=value; Path=/'
  assert.deepEqual(mergeSetCookieHeaders(a, [b, a], undefined, b), [a, b])
  assert.deepEqual(mergeSetCookieHeaders(undefined, null, []), [])
  assert.equal(setCookieBytes([a, b]), Buffer.byteLength(a) + 16 + Buffer.byteLength(b) + 16)
})
