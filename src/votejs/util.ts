import {LargeInteger, ModPGroup, ModPGroupElement, PField, PGroup, PPGroup} from 'verificatum/arithm'
import {PrivateKey, PublicKey, Ciphertext} from 'votejs/types';
import {Hex} from 'verificatum/types';
import {ByteTree} from 'verificatum/eio';

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
};

export const convert = {
    skToHex(sk: PrivateKey): Hex {
      return sk.value.toHexString();
    },
    // TODO support elliptic curves
    pkToHex(pk: PublicKey<ModPGroup, ModPGroupElement>): Hex {
      return pk.values[1].value.toHexString();
    },
    // TODO support elliptic curves (consider to make it generic)
    skFromHex(skHex: Hex, group: ModPGroup): PrivateKey {
        let skLargeInt = new LargeInteger(skHex);
        let skPfield = new PField(group.getElementOrder());
        return skPfield.toElement(skLargeInt.toByteArray());
    },
    // TODO support elliptic curves
    pkFromHex(pkHex: Hex, group: ModPGroup): PublicKey<ModPGroup, ModPGroupElement> {
        let pkLargeInt = new LargeInteger(pkHex);
        let pkTree = new ByteTree(pkLargeInt.toByteArray(257)); // It doesn't work without 257
        let pkModG = group.toElement(pkTree);
        let g = group.getg();
        let pkGroup = new PPGroup<ModPGroup, ModPGroupElement>([group, group]);
        return pkGroup.prod([g, pkModG]);
    },
    serializeCipher(cipher: Ciphertext<ModPGroup, ModPGroupElement>) {
        return {
            alpha:  cipher.values[0].value.toHexString(),
            beta:   cipher.values[1].value.toHexString()
        };
    },
    deserializeCipher(group: ModPGroup, cipher: {alpha: string, beta:string}) {
        let alphaInt = new LargeInteger(cipher['alpha']);
        let betaInt = new LargeInteger(cipher['beta']);
        let alphaTree = new ByteTree(alphaInt.toByteArray(257));
        let betaTree = new ByteTree(betaInt.toByteArray(257));
        let alpha = group.toElement(alphaTree);
        let beta = group.toElement(betaTree);
        let cipherGroup = new PPGroup<ModPGroup, ModPGroupElement>([group, group]);
        return cipherGroup.prod([alpha, beta]);
    }
};
