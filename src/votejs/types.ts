import { Hex } from 'verificatum/types'
import { LargeInteger, PPGroupElement, PFieldElement } from 'verificatum/arithm'

export type Choice = Array<number>

export interface Ciphertext {
  a: LargeInteger
  b: LargeInteger
}

export interface ChoiceEncoder {
  encode(choices: Choice, nrOptions?: number): LargeInteger
}

export interface CryptoSystem<G, E> {
  prove(cipher: Ciphertext, random: Hex): boolean
  decrypt(key: PrivateKey<G, E>, cipher: Ciphertext): string
  encrypt(key: PublicKey<G, E>, message: string): Ciphertext
}

export interface Scheme {
  module: CryptoSystem<any, any>
  encoder: ChoiceEncoder
}

export type PrivateKey<G, E> = PPGroupElement<G, E>
export type PublicKey<G, E> = PFieldElement
export type KeyPair<G, E> = [PPGroupElement<G, E>, PFieldElement]
