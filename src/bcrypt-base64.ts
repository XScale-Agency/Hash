/**
 * Bcrypt does not use standard base64 encoding.
 * https://hackernoon.com/the-bcrypt-protocol-is-kind-of-a-mess-4aace5eb31bd
 */

/**
 * bcrypt's own non-standard base64 dictionary.
 **/
const base64Code = [...'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789']

const base64Index = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 54,
  55, 56, 57, 58, 59, 60, 61, 62, 63, -1, -1, -1, -1, -1, -1, -1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
  12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, -1, -1, -1, -1, -1, -1, 28, 29,
  30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
  -1, -1, -1, -1, -1,
]

/**
 * Encodes a Buffer to base64 using the bcrypt's base64 dictionary.
 */
export const encode = (buff: Uint8Array) => {
  const length = buff.byteLength

  let off = 0

  const chars: string[] = []

  while (off < length) {
    let c1 = buff[off++] & 0xff

    chars.push(base64Code[(c1 >> 2) & 0x3f])

    c1 = (c1 & 0x03) << 4

    if (off >= length) {
      chars.push(base64Code[c1 & 0x3f])
      break
    }

    let c2 = buff[off++] & 0xff

    c1 |= (c2 >> 4) & 0x0f

    chars.push(base64Code[c1 & 0x3f])

    c1 = (c2 & 0x0f) << 2

    if (off >= length) {
      chars.push(base64Code[c1 & 0x3f])
      break
    }

    c2 = buff[off++] & 0xff

    c1 |= (c2 >> 6) & 0x03

    chars.push(base64Code[c1 & 0x3f], base64Code[c2 & 0x3f])
  }

  return chars.join('')
}

/**
 * Decodes a base64 encoded string using the bcrypt's base64 dictionary.
 */
export const decode = (string: string) => {
  let off = 0
  let olen = 0

  const stringLength = string.length

  const chars = []

  const { length } = string

  while (off < stringLength - 1 && olen < length) {
    let code = string.codePointAt(off++)

    if (!code) break

    const c1 = code < base64Index.length ? base64Index[code] : -1

    code = string.codePointAt(off++)

    if (!code) break

    const c2 = code < base64Index.length ? base64Index[code] : -1

    if (c1 === -1 || c2 === -1) break

    let o = (c1 << 2) >>> 0

    o |= (c2 & 0x30) >> 4

    chars.push(String.fromCodePoint(o))

    if (++olen >= length || off >= stringLength) break

    code = string.codePointAt(off++)

    if (!code) break

    const c3 = code < base64Index.length ? base64Index[code] : -1

    if (c3 === -1) break

    o = ((c2 & 0x0f) << 4) >>> 0

    o |= (c3 & 0x3c) >> 2

    chars.push(String.fromCodePoint(o))

    if (++olen >= length || off >= stringLength) break

    code = string.codePointAt(off++)

    if (!code) break

    const c4 = code < base64Index.length ? base64Index[code] : -1

    o = ((c3 & 0x03) << 6) >>> 0
    o |= c4
    chars.push(String.fromCodePoint(o))
    ++olen
  }

  const bufferArray = []

  for (off = 0; off < olen; off++) {
    const codePoint = chars[off].codePointAt(0)
    if (codePoint !== undefined) {
      bufferArray.push(codePoint)
    }
  }

  return Buffer.from(bufferArray)
}
