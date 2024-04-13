import { test } from '@japa/runner'
import { Hash } from '../src/hash.js'
import { Argon } from '../src/driver/argon.js'

test.group('Hash', () => {
  test('hash text using a driver', async ({ assert }) => {
    const argon = new Argon()
    const hash = new Hash(argon)

    const hashedValue = await hash.make('secret')
    assert.isTrue(hash.isValidHash(hashedValue))
  })

  test('verify hash using a driver', async ({ assert }) => {
    const argon = new Argon()
    const hash = new Hash(argon)

    const hashedValue = await hash.make('secret')
    assert.isTrue(await hash.verify(hashedValue, 'secret'))
  })

  test('check if hash needs to be rehashed using a driver', async ({ assert }) => {
    const argon = new Argon()
    const hash = new Hash(argon)

    const hashedValue = await hash.make('secret')
    assert.isFalse(hash.needsReHash(hashedValue))
  })

  test('assert hashed value against plain value', async ({ assert }) => {
    const argon = new Argon()
    const hash = new Hash(argon)

    const hashedValue = await hash.make('secret')

    await assert.doesNotRejects(async () => hash.assertEquals(hashedValue, 'secret'))

    await assert.rejects(
      async () => hash.assertEquals(hashedValue, 'sere'),
      'Expected "sere" to pass hash verification'
    )

    await assert.doesNotRejects(async () => hash.assertNotEquals(hashedValue, 'sere'))

    await assert.rejects(
      async () => hash.assertNotEquals(hashedValue, 'secret'),
      'Expected "secret" to fail hash verification'
    )
  })
})
