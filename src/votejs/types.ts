import { Hex } from 'verificatum/types'
import { LargeInteger } from 'verificatum/arithm'

export type Choice = Array<number>

export interface Ciphertext {
  a: LargeInteger
  b: LargeInteger
}

export interface ChoiceEncoder {
  encode(choices: Choice, nrOptions?: number): LargeInteger
}

export interface PrivateKey {}
export interface PublicKey {}

export interface CryptoSystem {
  prove(cipher: Ciphertext, random: Hex): boolean
  decrypt(key: PrivateKey, cipher: Ciphertext): string
  encrypt(key: PublicKey, message: string): Ciphertext
}

export interface Scheme {
  module: CryptoSystem
  encoder: ChoiceEncoder
}
