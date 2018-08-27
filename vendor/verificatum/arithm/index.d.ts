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
    square(): LargeInteger
    divQR(divisor:LargeInteger): [LargeInteger, LargeInteger]
}

export interface GroupElement<T> {
    equals(other:T): boolean
    mul(other:T): T
    exp(): T
}


declare class PGroup<E> {
    randomElement(source:RandomSource, dist:number): E
}

declare class PGroupElement<G> {
    pGroup: G
    value: LargeInteger
}

export class PRing {}
export class PRingElement<R> {
    pRing: R
    value: LargeInteger
}


export class PPGroup<E> extends PGroup<E> {}
export class PPGroupElement<G, E> extends PGroupElement<G> {
    values: [E, E]
}

export class ECqPGroup extends PGroup<ECqPGroupElement> {}
export class ECqPGroupElement extends PGroupElement<ECqPGroup> {}

export class ModPGroup extends PGroup<ModPGroupElement> {
    constructor(modulus:LargeInteger, order:LargeInteger, group:LargeInteger, encoding:number)
}
export class ModPGroupElement extends PGroupElement<ModPGroup> {}

export class PPRing extends PRing {}
export class PPRingElement extends PRingElement<PPRing> {}

export class PField extends PRing {}
export class PFieldElement extends PRingElement<PField> {}