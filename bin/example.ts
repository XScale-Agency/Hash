import { Hash, Scrypt } from '../index.js'

const hash = new Hash(new Scrypt())

const hashed = await hash.make('user_password')

console.log(hashed)
