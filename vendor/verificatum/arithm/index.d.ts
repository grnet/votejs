import { Hex, ByteArray } from 'verificatum/types'
import { RandomSource } from 'verificatum/crypto'
import { ByteTree } from '../eio/index'

export class LargeInteger {
  constructor(sign: string, value: ByteArray)
  constructor(length: number, source: RandomSource)
  constructor(hex: Hex)

  static ZERO: LargeInteger
  static ONE: LargeInteger
  static TWO: LargeInteger

  value: Array<number>

  bitLength(): number
  cmp(num: LargeInteger): number
  toHexString(): string
  iszero(): boolean
  equals(other: LargeInteger): boolean
  mul(other: LargeInteger): LargeInteger
  sub(other: LargeInteger): LargeInteger
  add(other: LargeInteger): LargeInteger
  div(other: LargeInteger): LargeInteger
  modPow(
    exponent: LargeInteger,
    modulus: LargeInteger,
    naive?: boolean
  ): LargeInteger
  // modPow(exponent:LargeInteger, modulus:LargeInteger): LargeInteger
  mod(modulus: LargeInteger): LargeInteger
  square(): LargeInteger
  divQR(divisor: LargeInteger): [LargeInteger, LargeInteger]
  toByteArray(byteSize?: number): number[]
  legendre(modulus: LargeInteger): number
}

export interface GroupElement<T> {
  equals(other: T): boolean
  mul(other: T): T
  exp(): T
}

declare class PGroup<G, E, V> {
  modulusByteLength: number
  modulus: LargeInteger // FIXME move modulus to ModPGroup
  constructor(pRing: PRing)
  pRing: PField
  randomElement(source: RandomSource, dist: number): E
  getElementOrder(): LargeInteger
  getg(): PGroupElement<G, V>
  toElement(byteTree: ByteTree): E
  encode(bytes: ByteArray, index: number, length: number): E
}

declare class PGroupElement<G, V> {
  pGroup: G
  value: V
  equals(other: PGroupElement<G, V>): boolean
}

export class PRing {
  randomElement(source: RandomSource, dist: number): PRingElement<PRing>
  toElement(byteTree: ByteArray): PRingElement<PRing>
}
export class PRingElement<R> {
  pRing: R
  value: LargeInteger
}

export class PPGroup<G, E, V> extends PGroup<G, E, V> {
  constructor(value: PGroup<G, E, V>[] | PGroup<G, E, V>, width?: number)
  prod(value: any): PPGroupElement<G, E>
}
export class PPGroupElement<G, E> extends PGroupElement<G, E> {
  values: [E, E]
}

export class ModPGroup extends PGroup<
  ModPGroup,
  ModPGroupElement,
  LargeInteger
> {
  constructor(
    modulus: LargeInteger,
    order: LargeInteger,
    group: LargeInteger,
    encoding: number
  )
}
export class ModPGroupElement extends PPGroupElement<ModPGroup, LargeInteger> {}

export class PPRing extends PRing {}
export class PPRingElement extends PRingElement<PPRing> {}

export class PField extends PRing {
  constructor(order?: string | number | LargeInteger)
}
export class PFieldElement extends PRingElement<PField> {}
