import { Hex, ByteArray } from "verificatum/types";
import { RandomSource } from "verificatum/crypto";

export class LargeInteger {

    constructor(sign:string, value:ByteArray)
    constructor(length:number, source:RandomSource)
    constructor(hex:Hex)

    static ZERO: LargeInteger
    static ONE: LargeInteger
    static TWO: LargeInteger

    value: Array<number>

    cmp(num:LargeInteger): number
    toHexString(): string
    iszero(): boolean
    equals(other:LargeInteger): boolean
    mul(other:LargeInteger): LargeInteger 
    sub(other:LargeInteger): LargeInteger
    add(other:LargeInteger): LargeInteger
    modPow(exponent:LargeInteger, modulus:LargeInteger, naive: boolean): LargeInteger
    modPow(exponent:LargeInteger, modulus:LargeInteger): LargeInteger
}

export interface GroupElement<T> {
    equals(other:T): boolean
    mul(other:T): T
    exp(): T
}

export interface ModPGroupElement extends GroupElement<ModPGroupElement> {
    pGroup: ModPGroup
    value: LargeInteger
}

export class ModPGroup {
    constructor(modulus:LargeInteger, order:LargeInteger, group:LargeInteger, encoding:number)
    randomElement(source:RandomSource, dist:number): ModPGroupElement
}
