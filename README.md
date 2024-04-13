# PHC Formatter

PHC Formatter serializes and deserializes PHC strings.

## Install

```bash
yarn add @xscale/phc-formatter
```

## Usage

```ts
import * as PHCFormatter from '../index.js'

const serialized = PHCFormatter.serialize({
  id: 'pbkdf2-sha256',
  salt: Buffer.from('0ZrzXitFSGltTQnBWOsdAw', 'base64'),
  hash: Buffer.from('Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'base64'),
  version: 1,
  parameters: {
    i: 1000,
    m: 1024,
    p: 8,
  },
})

console.log(serialized)

// $pbkdf2-sha256$v=1$i=1000,m=1024,p=8$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M$0ZrzXitFSGltTQnBWOsdAw

const parsed = PHCFormatter.deserialize(serialized)

console.log(parsed)

// {
//   id: 'pbkdf2-sha256',
//   hash: <Buffer 63 5d 40 72 1a 95 e1 bd 2c 52 2b 1d 65 dd 17 af de ca 5a 8c a6 34 4d 0b 34 da e7 12 06 38 1f d3>,
//   salt: <Buffer d1 9a f3 5e 2b 45 48 69 6d 4d 09 c1 58 eb 1d 03>,
//   version: 1,
//   parameters: { i: 1000, m: 1024, p: 8 }
// }
```

## API

### `serialize(phc: PHC): string`

Serializes a PHC object into a PHC string.

### `deserialize(phc: string): PHC`

Deserializes a PHC string into a PHC object.

### `PHC`

```ts
type PhcNode = {
  id: string
  hash: Uint8Array
  salt: Uint8Array
  version?: number
  parameters?: Record<string, number>
}
```