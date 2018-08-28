import { Hex } from 'verificatum/types'
import {LargeInteger, PPGroupElement, PFieldElement, PGroupElement} from 'verificatum/arithm'

export type Choice = Array<number>

/**
 * Represents a ciphertext composed of a tuple of group elements
 * @template E (ModPGroupElement | ECqPGroupElement)
 */
export interface Ciphertext<E> {
  a: E
  b: E
}

export interface ChoiceEncoder {
  encode(choices: Choice, nrOptions?: number): LargeInteger
}

export interface CryptoSystem<G, E> {
  prove(cipher: Ciphertext<E>, random: Hex): boolean
  decrypt(key: PrivateKey, cipher: Ciphertext<E>): E
  encrypt(key: PublicKey<G, E>, message: E): Ciphertext<E>
}

export interface Scheme {
  module: CryptoSystem<any, any>
  encoder: ChoiceEncoder
}

export type PrivateKey = PFieldElement
export type PublicKey<G, E> = PPGroupElement<G, E>
export type KeyPair<G, E> = [PPGroupElement<G, E>, PFieldElement]
