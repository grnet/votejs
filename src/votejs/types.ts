import { Hex } from 'verificatum/types'
import {LargeInteger, PPGroupElement, PFieldElement, PGroupElement} from 'verificatum/arithm'

export type Choice = Array<number>

export interface ChoiceEncoder {
  encode(choices: Choice, nrOptions?: number): LargeInteger
}

export interface CryptoSystem<G, E> {
  prove(cipher: Ciphertext<G, E>, random: Hex): boolean
  decrypt(key: PrivateKey, cipher: Ciphertext<G, E>): E
  encrypt(key: PublicKey<G, E>, message: E): Ciphertext<G, E>
}

export interface Scheme {
  module: CryptoSystem<any, any>
  encoder: ChoiceEncoder
}

export type PrivateKey = PFieldElement
export type PublicKey<G, E> = PPGroupElement<G, E>
export type KeyPair<G, E> = [PPGroupElement<G, E>, PFieldElement]
export type Ciphertext<G, E> = PPGroupElement<G, E>
