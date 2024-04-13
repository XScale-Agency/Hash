import type bcrypt from 'bcrypt'
import * as PHCFormatter from '@xscale/phc-formatter'
import * as BcryptBase64 from '../bcrypt-base64.js'
import type { HashDriverContract, BcryptConfig } from '../types.js'
import { enumValidator, randomBytesAsync, rangeValidator, safeEqual } from '../helpers.js'

/**
 * Hash driver built on top of "bcrypt" hash algorigthm. Under the hood
 * we make use of the "bcrypt" npm package.
 *
 * The Bcrypt implementation uses the PHC formatting for creating
 * and verifying hashes.
 *
 * ```ts
 * const bcrypt = new Bcrypt({})
 *
 * await bcrypt.make('secret')
 * // $bcrypt$v=98$r=10$Jtxi46WJ26OQ0khsYLLlnw$knXGfuRFsSjXdj88JydPOnUIglvm1S8
 * ```
 */
export class Bcrypt implements HashDriverContract {
  /**
   * Lazily loaded bcrypt binding. Since it is a peer dependency
   * we cannot import it at top level
   */
  #binding?: typeof bcrypt

  /**
   * Config with defaults merged
   */
  readonly #config: Required<BcryptConfig>

  constructor(config?: BcryptConfig) {
    this.#config = {
      rounds: 10,
      saltSize: 16,
      version: 0x62,
      ...config,
    }

    this.#validateConfig()
  }

  /**
   * Check if the value is a valid hash. This method just checks
   * for the formatting of the hash.
   *
   * ```ts
   * bcrypt.isValidHash('hello world') // false
   * bcrypt.isValidHash('$bcrypt$v=98$r=10$Jtxi46WJ26OQ0khsYLLlnw$knXGfuRFsSjXdj88JydPOnUIglvm1S8')
   * ```
   */
  isValidHash(value: string): boolean {
    try {
      this.#validatePhcString(value)
      return true
    } catch {
      return false
    }
  }

  /**
   * Hash a plain text value
   *
   * ```ts
   * const hash = await bcrypt.make('password')
   * ```
   */
  async make(value: string) {
    const driver = await this.#importBinding()

    /**
     * Generate salt including bcrypt formatted salt
     */
    const salt = await randomBytesAsync(this.#config.saltSize)
    const bcryptSalt = this.#generateBcryptSalt(salt, this.#config.version, this.#config.rounds)

    /**
     * Generate hash
     */
    const bcryptHash = await driver.hash(value, bcryptSalt)
    const hash = BcryptBase64.decode(bcryptHash.split(bcryptSalt)[1])

    return PHCFormatter.serialize({
      id: 'bcrypt',
      salt,
      hash,
      version: this.#config.version,
      parameters: {
        r: this.#config.rounds,
      },
    })
  }

  /**
   * Verify the plain text value against an existing hash
   *
   * ```ts
   * if (await bcrypt.verify(hash, plainText)) {
   *
   * }
   * ```
   */
  async verify(hashedValue: string, plainValue: string): Promise<boolean> {
    const driver = await this.#importBinding()

    try {
      if (hashedValue.startsWith('$2b') || hashedValue.startsWith('$2a')) {
        return await driver.compare(plainValue, hashedValue)
      }

      /**
       * De-serialize hash and ensure all Phc string properties
       * to exist.
       */
      const phcNode = this.#validatePhcString(hashedValue)
      const bcryptSalt = this.#generateBcryptSalt(
        phcNode.salt,
        phcNode.version,
        phcNode.parameters.r
      )

      const bcryptHash = await driver.hash(plainValue, bcryptSalt)
      const hash = BcryptBase64.decode(bcryptHash.split(bcryptSalt)[1])

      return safeEqual(hash, phcNode.hash)
    } catch {
      return false
    }
  }

  /**
   * Find if the hash value needs a rehash or not. The rehash is
   * required when.
   *
   * 1. The bcrypt version is changed
   * 2. Number of rounds are changed
   * 3. Bcrypt hash is not using MCF hash format
   * 4. The provided hash has not been hashed with bcrypt
   *
   * ```ts
   * const isValid = await bcrypt.verify(hash, plainText)
   *
   * // Plain password is valid and hash needs a rehash
   * if (isValid && await bcrypt.needsReHash(hash)) {
   *   const newHash = await bcrypt.make(plainText)
   * }
   * ```
   */
  needsReHash(value: string): boolean {
    if (value.startsWith('$2b') || value.startsWith('$2a')) {
      return true
    }

    const phcNode = PHCFormatter.deserialize(value)
    if (phcNode.id !== 'bcrypt') {
      return true
    }

    /**
     * If config version is separate from hash version, then a
     * re-hash is needed
     */
    if (phcNode.version !== this.#config.version) {
      return true
    }

    /**
     * Make sure all the encoded parameters are same as the config.
     * Otherwise a re-hash is needed
     */
    if (!phcNode.parameters) {
      return true
    }

    if (phcNode.parameters.r !== this.#config.rounds) {
      return true
    }

    return false
  }

  /**
   * Dynamically importing underlying binding
   */
  async #importBinding() {
    if (this.#binding) {
      return this.#binding
    }

    this.#binding = await import('bcrypt')
    return this.#binding
  }

  /**
   * Generates salt for bcrypt
   */
  #generateBcryptSalt(salt: Uint8Array, version: number, rounds: number) {
    const bcryptVersionCharCode = String.fromCodePoint(version)
    const paddedRounds = rounds > 9 ? `${rounds}` : `0${rounds}`
    return `$2${bcryptVersionCharCode}$${paddedRounds}$${BcryptBase64.encode(salt)}`
  }

  /**
   * Validate config
   */
  #validateConfig() {
    rangeValidator('rounds', this.#config.rounds, [4, 31])
    rangeValidator('saltSize', this.#config.saltSize, [8, 1024])
    enumValidator('version', this.#config.version, [0x61, 0x62])
    Object.freeze(this.#config)
  }

  /**
   * Validate phc hash string
   */
  #validatePhcString(phcString: string) {
    const phcNode = PHCFormatter.deserialize(phcString)

    /**
     * Old bcrypt strings without version
     */
    phcNode.version ||= 0x61

    /**
     * Validate top level properties to exist
     */
    if (phcNode.id !== 'bcrypt') {
      throw new TypeError(`Invalid "id" found in the phc string`)
    }

    if (!phcNode.parameters) {
      throw new TypeError(`No "parameters" found in the phc string`)
    }

    if (!phcNode.salt) {
      throw new TypeError(`No "salt" found in the phc string`)
    }

    if (!phcNode.hash) {
      throw new TypeError(`No "hash" found in the phc string`)
    }

    if (!phcNode.hash.byteLength) {
      throw new TypeError(`No "hash" found in the phc string`)
    }

    rangeValidator('salt.byteLength', phcNode.salt.byteLength, [8, 1024])

    /**
     * Validate rest of the properties
     */
    enumValidator('version', phcNode.version, [0x61, 0x62])
    rangeValidator('r', phcNode.parameters.r, [4, 31])

    return {
      id: phcNode.id,
      version: phcNode.version,
      hash: phcNode.hash,
      salt: phcNode.salt,
      parameters: {
        r: phcNode.parameters.r,
      },
    }
  }
}
