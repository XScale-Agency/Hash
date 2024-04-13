import { promisify } from 'node:util'
import { randomBytes, scrypt, type ScryptOptions, timingSafeEqual } from 'node:crypto'
import { Buffer } from 'node:buffer'
import type { BufferSafeValue } from './types.js'

export const maxUint32 = 2 ** 32 - 1
export const maxUint24 = 2 ** 24 - 1

/**
 * Validates a number to be within a given range.
 */
export const rangeValidator = (label: string, value: unknown, range: [number, number]) => {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new TypeError(`The "${label}" option must be an integer`)
  }

  const [min, max] = range

  if (value < min || value > max) {
    throw new TypeError(`The "${label}" option must be in the range (${min} <= ${label} <= ${max})`)
  }
}

/**
 * Validates a value to be one of the allowed values
 */
export const enumValidator = (
  label: string,
  value: string | number,
  allowedValues: Array<string | number>
) => {
  if (!allowedValues.includes(value)) {
    throw new TypeError(`The "${label}" option must be one of: ${allowedValues.join(',')}`)
  }
}

/**
 * Async function to generate random bytes
 */
export const randomBytesAsync = promisify(randomBytes)

/**
 * Async version of scrypt.
 */
export const scryptAsync = promisify<string, Uint8Array, number, ScryptOptions, Uint8Array>(scrypt)

/**
 * Compare two values to see if they are equal. The comparison is done in
 * a way to avoid timing-attacks.
 */
export function safeEqual<T extends BufferSafeValue, U extends BufferSafeValue>(
  trustedValue: T,
  userInput: U
): boolean {
  if (typeof trustedValue === 'string' && typeof userInput === 'string') {
    /**
     * The length of the comparison value.
     */
    const trustedLength = Buffer.byteLength(trustedValue)

    /**
     * Expected value
     */
    const trustedValueBuffer = Buffer.alloc(trustedLength, 0, 'utf8')
    trustedValueBuffer.write(trustedValue)

    /**
     * Actual value (taken from user input)
     */
    const userValueBuffer = Buffer.alloc(trustedLength, 0, 'utf8')
    userValueBuffer.write(userInput)

    /**
     * Ensure values are same and also have same length
     */
    return (
      timingSafeEqual(trustedValueBuffer, userValueBuffer) &&
      trustedLength === Buffer.byteLength(userInput)
    )
  }

  return timingSafeEqual(
    Buffer.from(trustedValue as ArrayBuffer | SharedArrayBuffer),
    Buffer.from(userInput as ArrayBuffer | SharedArrayBuffer)
  )
}
