# Hash

The `@xscale/hash` package provides a platform-agnostic multi-driver hashing module that adheres to the PHC string format. It offers first-class support for popular algorithms like bcrypt, scrypt, and argon2, with the flexibility to add custom drivers.

## Usage

The `hash.make` method accepts a plain text string (typically a user password) and returns a hashed output.

```ts
import { Hash, Scrypt } from '@xscale/hash'

const hash = new Hash(new Scrypt())

const hashed = await hash.make('user_password')

// $scrypt$n=16384,r=8,p=1$awRyvKyosNsLRGqXQnKs1w$ePrdivX50POaYJ18x5r1+fU7Bfc232KFeqku3U/vZVD62JQycLuAVRdlLkM/lkdQQFS+CT6j32422lm58BRB1A
```

You cannot convert a hash value to plain text, hashing is a one-way process, and there is no way to retrieve the original value after a hash has been generated.

However, hashing provides a way to verify if a given plain text value matches against an existing hash, and you can perform this check using the hash.verify method.

```ts
if (await hash.verify(hashed, 'user_password')) {
  // Password is correct
} else {
  // Password is incorrect
}
```

---

## Configuration

You can configure the hash driver by passing an object to the constructor.

The default driver is set to scrypt because `scrypt` uses the Node.js native crypto module and does not require any third-party packages.

```ts
import { Hash, Scrypt } from '@xscale/hash'

const scryptHash = new Hash(new Scrypt())
```

### Argon

Argon is the recommended hashing algorithm to hash user passwords. To use argon with the hash service, you must install the argon2 npm package.

```bash
yarn add argon2
```

```ts
import { Hash, Argon } from '@xscale/hash'

const argonHash = new Hash(new Argon({
    version: 0x13, // hex code for 19
    variant: 'id',
    iterations: 3,
    memory: 65536,
    parallelism: 4,
    saltSize: 16,
    hashLength: 32,
}))
```

<dt>

**variant**

</dt>

<dd>

The argon hash variant to use.

- `d` is faster and highly resistant against GPU attacks, which is useful for cryptocurrency
- `i` is slower and resistant against tradeoff attacks, which is preferred for password hashing and key derivation.
- `id` *(default)* is a hybrid combination of the above, resistant against GPU and tradeoff attacks.

</dd>

---

<dt>

**version**

</dt>

<dd>

The argon version to use. The available options are `0x10 (1.0)` and `0x13 (1.3)`. The latest version should be used by default.

</dd>

---

<dt>

**iterations**

</dt>

<dd>

The `iterations` count increases the hash strength but takes more time to compute. 

The default value is `3`.

</dd>

---

<dt>

**memory**

</dt>

<dd>

The amount of memory to be used for hashing the value. Each parallel thread will have a memory pool of this size. 

The default value is `65536 (KiB)`.

</dd>

---

<dt>

**parallelism**

</dt>

<dd>

The number of threads to use for computing the hash. 

The default value is `4`.

</dd>

---

<dt>

**saltSize**

</dt>

<dd>

The length of salt (in bytes). Argon generates a cryptographically secure random salt of this size when computing the hash.

The default and recommended value for password hashing is `16`.

</dd>

---

<dt>

**hashLength**

</dt>

<dd>

Maximum length for the raw hash (in bytes). The output value will be longer than the mentioned hash length because the raw hash output is further encoded to PHC format.

The default value is `32`

</dd>

### Bcrypt

```bash
yarn add bcrypt
```

```ts
import { Hash, Bcrypt } from '@xscale/hash'

const bcryptHash = new Hash(new Bcrypt({
    rounds: 10,
    saltSize: 16,
    version: '2b'
}))
```

---

<dt>

***rounds***

</dt>

<dd>

The cost for computing the hash. We recommend reading the [A Note on Rounds](https://github.com/kelektiv/node.bcrypt.js#a-note-on-rounds) section from Bcrypt docs to learn how the `rounds` value has an impact on the time it takes to compute the hash.

The default value is `10`.

</dd>

---

<dt>

***saltSize***

</dt>

<dd>

The length of salt (in bytes). When computing the hash, we generate a cryptographically secure random salt of this size.

The default value is `16`.

</dd>

---

<dt>

**version**

</dt>

<dd>

The version for the hashing algorithm. The supported values are `2a` and `2b`. Using the latest version, i.e., `2b` is recommended.

</dd>

</dl>

### Scrypt

The scrypt driver uses the Node.js crypto module for computing the password hash. The configuration options are the same as those accepted by the [Node.js `scrypt` method](https://nodejs.org/dist/latest-v19.x/docs/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback).

```ts
import { Hash, Scrypt } from '@xscale/hash'

const scryptHash = new Hash(new Scrypt({
  cost: 16384,
  blockSize: 8,
  parallelization: 1,
  saltSize: 16,
  maxMemory: 33554432,
  keyLength: 64
}))
```

---

## Checking if a password needs to be rehashed

The latest configuration options are recommended to keep passwords secure, especially when a vulnerability is reported with an older version of the hashing algorithm.

After you update the config with the latest options, you can use the `hash.needsReHash` method to check if a password hash uses old options and perform a re-hash.

The check must be performed during user login because that is the only time you can access the plain text password.

```ts
if (await hash.needsReHash(hashed)) {
  const newHash = await hash.make('user_password')
  // Update the user password with the new hash
}
```

## Creating a custom hash driver

A hash driver must implement the [HashDriverContract](https://github.com/XScale-Agency/Hash/blob/d6b36347654a799dcf8261b8a6e56e8958d02970/src/types.ts#L1) interface. Also, the official Hash drivers use [PHC format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) to serialize the hash output for storage. You can check the existing driver's implementation to see how they use the [PHC formatter](https://github.com/XScale-Agency/Hash/blob/main/src/driver/bcrypt.ts) to make and verify hashes.

```ts
import {
  HashDriverContract,
} from '@xscale/hash'

/**
 * Config accepted by the hash driver
 */
export type PbkdfConfig = {
}

/**
 * Driver implementation
 */
export class Pbkdf2Driver implements HashDriverContract {
  constructor(public config: PbkdfConfig) {
  }

  /**
   * Check if the hash value is formatted as per
   * the hashing algorithm.
   */
  isValidHash(value: string): boolean {
  }

  /**
   * Convert raw value to Hash
   */
  async make(value: string): Promise<string> {
  }

  /**
   * Verify if the plain value matches the provided
   * hash
   */
  async verify(
    hashedValue: string,
    plainValue: string
  ): Promise<boolean> {
  }

  /**
   * Check if the hash needs to be re-hashed because
   * the config parameters have changed
   */
  needsReHash(value: string): boolean {
  }
}
```

In the above code example, we export the following values.

- `PbkdfConfig`: TypeScript type for the configuration you want to accept.

- `Pbkdf2Driver`: The class that implements the `HashDriverContract` interface.

### Using the driver

Once you have created the driver, you can use it with the Hash service.

```ts
import { Hash } from '@xscale/hash'
import { Pbkdf2Driver } from 'path/to/driver'

const hash = new Hash(new Pbkdf2Driver({
  // Your config
}))
```

## Vulnerability Reporting

If you discover a security vulnerability within this package, please report it to [Github Security](https://github.com/XScale-Agency/Hash/security)