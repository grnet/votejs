import { ByteArray } from "verificatum/types";
import { ModPGroup } from "verificatum/arithm";

export class RandomSource {
    getBytes(len: number):ByteArray
}

export class ArithmObject {}
export class RandomDevice extends RandomSource {}
export class SHA256PRG extends RandomDevice {}
export interface CryptoSystem {}

export class ElGamal implements CryptoSystem  {
    constructor(standard:boolean, group: ModPGroup, source:RandomSource, dist:number)
}