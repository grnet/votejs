import {
    ECqPGroup,
    ECqPGroupElement,
    LargeInteger,
    ModPGroup,
    ModPGroupElement,
    PField,
    PGroup,
    PPGroup, PPGroupElement
} from 'verificatum/arithm'
import { PrivateKey, PublicKey, Ciphertext } from 'votejs/types'
import { Hex } from 'verificatum/types'
import { ByteTree } from 'verificatum/eio'
import {EC, ECP} from 'verificatum/arithm/ec';
import {hex} from '../../vendor/verificatum/arithm/sli/index';

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
  }
}

export const convert = {
  getAffine(curve: EC, point: ECP) {
    curve.affine(point);
    return point;
  },
  toGroupElement(n: LargeInteger, group: ModPGroup) {
    return group.toElement(new ByteTree(n.toByteArray(257)))
  },
  toFieldElement(n: LargeInteger, group: ModPGroup) {
    let skPfield = new PField(group.getElementOrder())
    return skPfield.toElement(n.toByteArray(257))
  },
  elementFromHex(hex: Hex, group: PGroup<any, any>) {
    return convert.toGroupElement(new LargeInteger(hex), group)
  },
  ecElementFromHex(hex: Array<Hex>, group: ECqPGroup): ECqPGroupElement {
    let xLargeInt = new LargeInteger(hex[0]);
    let yLargeInt = new LargeInteger(hex[1]);
    let len = group.modulusByteLength;
    let xByteTree = new ByteTree(xLargeInt.toByteArray(len));
    let yByteTree = new ByteTree(yLargeInt.toByteArray(len));
    let elemByteTree = new ByteTree([xByteTree, yByteTree]);
    return group.toElement(elemByteTree);
  },
  ecPPElementFromHex(
    hex: Array<Hex>,
    group: ECqPGroup
  ): PPGroupElement<ECqPGroup, ECqPGroupElement> {
    let groupElement = convert.ecElementFromHex(hex, group);
    let gh = group.getg();
    let elemPPGroup = new PPGroup<ECqPGroup, ECqPGroupElement>([group, group]);
    return elemPPGroup.prod([gh, groupElement]);
  },
  skToHex(sk: PrivateKey): Hex {
    return sk.value.toHexString()
  },
  pkToHexModP(pk: PublicKey<ModPGroup, ModPGroupElement>): Hex {
    return pk.values[1].value.toHexString()
  },
  pkToHexECqP(pk: PublicKey<ECqPGroup, ECqPGroupElement>): Array<Hex> {
    let curve = pk.values[0].pGroup.curve;
    let affinePk = convert.getAffine(curve, pk.values[1].value);
    let x = hex(affinePk.x);
    let y = hex(affinePk.y);
    return [x, y];
  },
  skFromInt(skInt: LargeInteger, group: PGroup<any, any>) {
    return convert.toFieldElement(skInt, group)
  },
  skFromHex(skHex: Hex, group: PGroup<any, any>): PrivateKey {
    // return convert.skFromInt(new LargeInteger(skHex), group)
    let  groupOrder = group.getElementOrder();
    let skInt = new LargeInteger(skHex);
    let skPfield = new PField(groupOrder);
    return skPfield.toElement(skInt.toByteArray());
  },
  pkFromInt(pkInt: LargeInteger, group: ModPGroup) {
    let pkModG = convert.toGroupElement(pkInt, group)
    let g = group.getg()
    let pkGroup = new PPGroup<ModPGroup, ModPGroupElement>([group, group])
    return pkGroup.prod([g, pkModG])
  },
  pkFromHexModP(
    pkHex: Hex,
    group: ModPGroup
  ): PublicKey<ModPGroup, ModPGroupElement> {
    return convert.pkFromInt(new LargeInteger(pkHex), group)
  },
  pkFromHexECqP(
    pkHex: Array<Hex>,
    group: ECqPGroup
  ): PublicKey<ECqPGroup, ECqPGroupElement> {
    return convert.ecPPElementFromHex(pkHex, group)
  },
  serializeModPCipher(cipher: Ciphertext<ModPGroup, ModPGroupElement>) {
    return {
      alpha: cipher.values[0].value.toHexString(),
      beta: cipher.values[1].value.toHexString()
    }
  },
  // TODO maybe get curve from ciphertext
  serializeECqPCipher(
    curve: EC,
    cipher: Ciphertext<ECqPGroup, ECqPGroupElement>
  ) {
    let alphaPoint = cipher.values[0].value;
    let betaPoint = cipher.values[1].value;
    curve.affine(alphaPoint);
    curve.affine(betaPoint);
    return {
        alpha: [hex(alphaPoint.x), hex(alphaPoint.y)],
        beta: [hex(betaPoint.x), hex(betaPoint.y)]
    };
  },
  deserializeModPCipher(
    group: ModPGroup,
    cipher: { alpha: string; beta: string }
  ) {
    let alphaInt = new LargeInteger(cipher['alpha'])
    let betaInt = new LargeInteger(cipher['beta'])
    let alphaTree = new ByteTree(alphaInt.toByteArray(257))
    let betaTree = new ByteTree(betaInt.toByteArray(257))
    let alpha = group.toElement(alphaTree)
    let beta = group.toElement(betaTree)
    let cipherGroup = new PPGroup<ModPGroup, ModPGroupElement>([group, group])
    return cipherGroup.prod([alpha, beta])
  },
  deserializeECqPCipher(
    group: ECqPGroup,
    cipher: {alpha: Hex[], beta: Hex[]}
  ) {
    let len = group.modulusByteLength;
    let gh = group.getg();
    let alphaLargeIntX = new LargeInteger(cipher['alpha'][0]);
    let alphaLargeIntY = new LargeInteger(cipher['alpha'][1]);
    let alphaByteTreeX = new ByteTree(alphaLargeIntX.toByteArray(len));
    let alphaByteTreeY = new ByteTree(alphaLargeIntY.toByteArray(len));
    let alphaByteTree = new ByteTree([alphaByteTreeX, alphaByteTreeY]);
    let alpha = group.toElement(alphaByteTree);
    let betaLargeIntX = new LargeInteger(cipher['beta'][0]);
    let betaLargeIntY = new LargeInteger(cipher['beta'][1]);
    let betaByteTreeX = new ByteTree(betaLargeIntX.toByteArray(len));
    let betaByteTreeY = new ByteTree(betaLargeIntY.toByteArray(len));
    let betaByteTree = new ByteTree([betaByteTreeX, betaByteTreeY]);
    let beta = group.toElement(betaByteTree);
    let cipherGroup = new PPGroup<ECqPGroup, ECqPGroupElement>([group, group]);
    return cipherGroup.prod([alpha, beta]);
  }
}
