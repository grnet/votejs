import {
  LargeInteger,
  ModPGroup,
  ModPGroupElement,
  PField,
  PGroup,
  PPGroup
} from 'verificatum/arithm'
import { PrivateKey, PublicKey, Ciphertext } from 'votejs/types'
import { Hex } from 'verificatum/types'
import { ByteTree } from 'verificatum/eio'
import { RandomDevice, SHA256PRG } from 'verificatum/crypto'

export function getGroupParams(group: ModPGroup) {
  return {
    order: group.getElementOrder(),
    modulus: group.modulus,
    generator: group.getg().value
  }
}

export const arithm = {
  gt(num1: LargeInteger, num2: LargeInteger) {
    return num1.cmp(num2) > 0
  },
  gte(num1: LargeInteger, num2: LargeInteger) {
    return num1.cmp(num2) >= 0
  },
  lt(num1: LargeInteger, num2: LargeInteger) {
    return num1.cmp(num2) < 0
  },
  lte(num1: LargeInteger, num2: LargeInteger) {
    return num1.cmp(num2) <= 0
  },
  toLargeInteger(num: number): LargeInteger {
    return new LargeInteger(num.toString(16))
  },
  toNumber(num: LargeInteger): number {
    return parseInt(num.toHexString(), 16)
  },
  toHex(num: LargeInteger): string {
    return num.toHexString().replace(/^0+/, '')
  }
}

export const random = {
  // https://github.com/grnet/zeus/blob/master/zeus/core.py#L2206
  getRandomInt(
    minimum: LargeInteger,
    ceiling: LargeInteger,
    source?: RandomDevice
  ): LargeInteger {
    if (!source) {
      // initialize Random Source
      let randomSource = new RandomDevice()
      let seed = randomSource.getBytes(SHA256PRG.seedLength)
      source = new SHA256PRG()
      source.setSeed(seed)
    }
    // get bit length
    let top = ceiling.sub(minimum)
    let bitLength = top.bitLength()
    let r = new LargeInteger(bitLength, source)
    return r.add(minimum)
  }
}

export const convert = {
  toGroupElement(n: LargeInteger, group: ModPGroup) {
    return group.toElement(new ByteTree(n.toByteArray(257)))
  },
  toFieldElement(n: LargeInteger, group: ModPGroup) {
    let skPfield = new PField(group.getElementOrder())
    return skPfield.toElement(n.toByteArray(257))
  },
  elementFromHex(hex: Hex, group: PGroup<any, any, any>) {
    return convert.toGroupElement(new LargeInteger(hex), group)
  },
  skToHex(sk: PrivateKey): Hex {
    return sk.value.toHexString()
  },
  pkToHexModP(pk: PublicKey<ModPGroup, ModPGroupElement>): Hex {
    return pk.values[1].value.toHexString()
  },
  skFromInt(skInt: LargeInteger, group: PGroup<any, any, any>) {
    return convert.toFieldElement(skInt, group)
  },
  skFromHex(skHex: Hex, group: PGroup<any, any, any>): PrivateKey {
    // return convert.skFromInt(new LargeInteger(skHex), group)
    let groupOrder = group.getElementOrder()
    let skInt = new LargeInteger(skHex)
    let skPfield = new PField(groupOrder)
    return skPfield.toElement(skInt.toByteArray())
  },
  pkFromInt(pkInt: LargeInteger, group: ModPGroup) {
    let pkModG = convert.toGroupElement(pkInt, group)
    let g = group.getg()
    let pkGroup = new PPGroup<ModPGroup, ModPGroupElement, LargeInteger>([
      group,
      group
    ])
    return pkGroup.prod([g, pkModG])
  },
  pkFromHexModP(
    pkHex: Hex,
    group: ModPGroup
  ): PublicKey<ModPGroup, ModPGroupElement> {
    return convert.pkFromInt(new LargeInteger(pkHex), group)
  },
  serializeCipher(cipher: Ciphertext<ModPGroup, ModPGroupElement>) {
    return {
      alpha: cipher.values[0].value.toHexString(),
      beta: cipher.values[1].value.toHexString()
    }
  },
  deserializeCipher(group: ModPGroup, cipher: { alpha: string; beta: string }) {
    let alphaInt = new LargeInteger(cipher['alpha'])
    let betaInt = new LargeInteger(cipher['beta'])
    let alphaTree = new ByteTree(alphaInt.toByteArray(257))
    let betaTree = new ByteTree(betaInt.toByteArray(257))
    let alpha = group.toElement(alphaTree)
    let beta = group.toElement(betaTree)
    let cipherGroup = new PPGroup<ModPGroup, ModPGroupElement, LargeInteger>([
      group,
      group
    ])
    return cipherGroup.prod([alpha, beta])
  }
}
