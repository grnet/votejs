import { Hex, ByteArray } from "verificatum/types";
import { RandomSource } from "verificatum/crypto";
import { ECP } from "verificatum/arithm/ec";

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
    square(): LargeInteger
    divQR(divisor:LargeInteger): [LargeInteger, LargeInteger]
    toByteArray(byteSize?: number): string[] // TODO make it generic
}

export interface GroupElement<T> {
    equals(other:T): boolean
    mul(other:T): T
    exp(): T
}


declare class PGroup<G, E> {
    constructor(pRing: PRing)
    pRing: PField
    randomElement(source:RandomSource, dist:number): E
    getElementOrder(): LargeInteger
    getg(): LargeInteger
    toElement(param: any): PGroupElement<G, E> // TODO Byte tree representation of an element, or a raw byte array.
}

declare class PGroupElement<G, V> {
    pGroup: G
    value: V
    equals(other: PGroupElement<G, V>): boolean
}

export class PRing {
    randomElement(source:RandomSource, dist:number): PRingElement<PRing>
    toElement(param: any): PFieldElement // TODO Byte tree representation of an element, or a raw byte array.
}
export class PRingElement<R> {
    pRing: R
    value: LargeInteger
}

export class PPGroup<G, E> extends PGroup<G, E> {
    // TODO replace any (https://www.verificatum.org/api-vjsc/vjsc-1.1.1.js.html#line8126)
    constructor(value: any, width?: any)
    prod(value: any): PPGroupElement<G, E>
}
export class PPGroupElement<G, E> extends PGroupElement<G, E> {
    values: [E, E]
}

export class ECqPGroup extends PGroup<ECqPGroup, ECqPGroupElement> {
    // TODO make modulus generic
    constructor(modulus: any, a?: number, b?: number, gx?: number, gy?: number, n?: number)
}
export class ECqPGroupElement extends PGroupElement<ECqPGroup, ECP> {
    // TODO make x generic
    constructor(pGroup: ECqPGroup, x: any, y?: LargeInteger, z?: LargeInteger)
}

export class ModPGroup extends PGroup<ModPGroup, ModPGroupElement> {
    constructor(modulus:LargeInteger, order:LargeInteger, group:LargeInteger, encoding:number)
}
export class ModPGroupElement extends PGroupElement<ModPGroup, LargeInteger> {}

export class PPRing extends PRing {}
export class PPRingElement extends PRingElement<PPRing> {}

export class PField extends PRing {
    constructor(order?: string|number|LargeInteger)
}
export class PFieldElement extends PRingElement<PField> {}