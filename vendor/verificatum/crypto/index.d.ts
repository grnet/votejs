import { ByteArray } from "verificatum/types";
import { ModPGroup, PRingElement, PGroupElement, PFieldElement, PPGroupElement, PGroup, KeyPair } from "verificatum/arithm";

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

export class ElGamal<G extends PGroup<E>, E extends PGroupElement<G>> implements CryptoSystem  {
    constructor(standard:boolean, group: ModPGroup, source:RandomSource, dist:number)
    gen(): KeyPair<G, E>
}