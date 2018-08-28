import { ByteArray } from "verificatum/types";
import { PGroupElement, PGroup} from "verificatum/arithm";
import {KeyPair} from 'votejs/types';

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

export class ElGamal<G extends PGroup<E>, V, E extends PGroupElement<G, V>> implements CryptoSystem  {
    constructor(standard:boolean, group: G, source:RandomSource, dist:number)
    gen(): KeyPair<G, E>
}