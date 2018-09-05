import { ByteArray } from "verificatum/types";
import {PGroupElement, PGroup, PFieldElement, PPGroupElement, ModPGroup, LargeInteger, ModPGroupElement} from "verificatum/arithm";
import {Ciphertext, KeyPair} from 'votejs/types';

export class RandomSource {
    getBytes(len: number):ByteArray
    setSeed(seed:ByteArray): null
}

export class ArithmObject {}
export class RandomDevice extends RandomSource {}
export class SHA256PRG extends RandomDevice {
    static seedLength: number
}
export interface CryptoSystem {}

export class ElGamal<G extends PGroup<G, E, V>, V, E extends PGroupElement<G, V>> implements CryptoSystem  {
    constructor(standard:boolean, group: G, source:RandomSource, dist:number)
    gen(): KeyPair<G, E>
    encrypt(publicKey: PPGroupElement<G, E>, message: E, random: PFieldElement): Ciphertext<G, E>
    decrypt(privateKey: PFieldElement, ciphertext: Ciphertext<G, E>): E
}
export type ModPElGamal = ElGamal<ModPGroup, LargeInteger, ModPGroupElement>