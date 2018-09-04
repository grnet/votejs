import { Hex, ByteArray } from "verificatum/types";
import { RandomSource } from "verificatum/crypto";
import {EC, ECP} from "verificatum/arithm/ec";
import {ByteTree} from '../eio/index';

export class LargeInteger {

    constructor(sign:string, value:ByteArray)
    constructor(length:number, source:RandomSource)
    constructor(hex:Hex)

    static ZERO: LargeInteger
    static ONE: LargeInteger
    static TWO: LargeInteger

    value: Array<number>

    bitLength(): number
    cmp(num:LargeInteger): number
    toHexString(): string
    iszero(): boolean
    equals(other:LargeInteger): boolean
    mul(other:LargeInteger): LargeInteger
    sub(other:LargeInteger): LargeInteger
    add(other:LargeInteger): LargeInteger
    modPow(exponent:LargeInteger, modulus:LargeInteger, naive?: boolean): LargeInteger
    mod(modulus: LargeInteger): LargeInteger
    square(): LargeInteger
    divQR(divisor:LargeInteger): [LargeInteger, LargeInteger]
    toByteArray(byteSize?: number): number[]
    legendre(modulus:LargeInteger): number
}

export interface GroupElement<T> {
    equals(other:T): boolean
    mul(other:T): T
    exp(): T
}


declare class PGroup<G, E> {
    modulusByteLength: number
    modulus: LargeInteger
    constructor(pRing: PRing)
    pRing: PField
    randomElement(source:RandomSource, dist:number): E
    getElementOrder(): LargeInteger
    getg(): LargeInteger
    toElement(byteTree: ByteTree): E
    encode(bytes:ByteArray, index:number, length: number): E
}

declare class PGroupElement<G, V> {
    pGroup: G
    value: V
    equals(other: PGroupElement<G, V>): boolean
}

export class PRing {
    randomElement(source:RandomSource, dist:number): PRingElement<PRing>
    toElement(byteTree: ByteArray): PRingElement<PRing>
}
export class PRingElement<R> {
    pRing: R
    value: LargeInteger
}

export class PPGroup<G, E> extends PGroup<G, E> {
    constructor(value: PGroup<G, E>[]|PGroup<G, E>, width?: number)
    prod(value: any): PPGroupElement<G, E>
}
export class PPGroupElement<G, E> extends PGroupElement<G, E> {
    values: [E, E]
}

export class ECqPGroup extends PGroup<ECqPGroup, ECqPGroupElement> {
    constructor(modulus: string|LargeInteger, a?: LargeInteger, b?: LargeInteger,
                gx?: LargeInteger, gy?: LargeInteger, n?: LargeInteger)
    curve: EC
}
export class ECqPGroupElement extends PGroupElement<ECqPGroup, ECP> {
    constructor(pGroup: ECqPGroup, x: ECP|LargeInteger, y?: LargeInteger, z?: LargeInteger)
}

export class ModPGroup extends PGroup<ModPGroup, ModPGroupElement> {
    constructor(modulus:LargeInteger, order:LargeInteger, group:LargeInteger, encoding:number)
}
export class ModPGroupElement extends PPGroupElement<ModPGroup, LargeInteger> {}

export class PPRing extends PRing {}
export class PPRingElement extends PRingElement<PPRing> {}

export class PField extends PRing {
    constructor(order?: string|number|LargeInteger)
}
export class PFieldElement extends PRingElement<PField> {}
