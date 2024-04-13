import { AssertionError } from 'node:assert'
import type { HashDriverContract } from './types.js'

/**
 * Hash and verify values using a dedicated hash driver. The Hash
 * works as an adapter across different drivers.
 *
 * ```ts
 * const hash = new Hash(new Argon())
 * const hashedPassword = await hash.make('secret')
 *
 * const isValid = await hash.verify(hashedPassword, 'secret')
 * console.log(isValid)
 * ```
 */
export class Hash implements HashDriverContract {
  readonly #driver: HashDriverContract

  constructor(driver: HashDriverContract) {
    this.#driver = driver
  }

  /**
   * Check if the value is a valid hash. This method just checks
   * for the formatting of the hash
   */
  isValidHash(value: string): boolean {
    return this.#driver.isValidHash(value)
  }

  /**
   * Hash plain text value
   */
  async make(value: string): Promise<string> {
    return this.#driver.make(value)
  }

  /**
   * Verify the plain text value against an existing hash
   */
  async verify(hashedValue: string, plainValue: string): Promise<boolean> {
    return this.#driver.verify(hashedValue, plainValue)
  }

  /**
   * Find if the hash value needs a rehash or not.
   */
  needsReHash(hashedValue: string): boolean {
    return this.#driver.needsReHash(hashedValue)
  }

  /**
   * Assert the plain value passes the hash verification
   */
  async assertEquals(hashedValue: string, plainValue: string): Promise<void> {
    const isEqual = await this.#driver.verify(hashedValue, plainValue)
    if (!isEqual) {
      throw new AssertionError({
        message: `Expected "${plainValue}" to pass hash verification`,
        expected: true,
        actual: false,
        operator: 'strictEqual',
        stackStartFn: this.assertEquals,
      })
    }
  }

  /**
   * Assert the plain value fails the hash verification
   */
  async assertNotEquals(hashedValue: string, plainValue: string): Promise<void> {
    const isEqual = await this.#driver.verify(hashedValue, plainValue)
    if (isEqual) {
      throw new AssertionError({
        message: `Expected "${plainValue}" to fail hash verification`,
        expected: false,
        actual: true,
        operator: 'strictEqual',
        stackStartFn: this.assertNotEquals,
      })
    }
  }
}
