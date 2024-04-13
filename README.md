# Hash

Multi driver hashing module following PHC string format

It has first-class support for bcrypt, scrypt, and argon2 hashing algorithms and the ability to add custom drivers.

## Usage

The hash.make method accepts a plain string value (the user password input) and returns a hash output.

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

```ts
import { Hash, Scrypt, Argon, Bcrypt } from '@xscale/hash'

const scryptHash = new Hash(new Scrypt({
    cost: 16384,
    blockSize: 8,
    parallelization: 1,
    saltSize: 16,
    maxMemory: 33554432,
    keyLength: 64
}))

const argonHash = new Hash(new Argon({
    version: 0x13, // hex code for 19
    variant: 'id',
    iterations: 3,
    memory: 65536,
    parallelism: 4,
    saltSize: 16,
    hashLength: 32,
}))

const bcryptHash = new Hash(new Bcrypt({
    rounds: 10,
    saltSize: 16,
    version: '2b'
}))
```

