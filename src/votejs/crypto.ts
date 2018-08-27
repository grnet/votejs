import { LargeInteger, ModPGroup } from 'verificatum/arithm'
import { Hex } from 'verificatum/types'
import { ChoiceEncoder, Scheme, CryptoSystem, Ciphertext } from 'votejs/types'
import { SHA256PRG, ElGamal } from 'verificatum/crypto'
import { GammaEncoder } from 'votejs/encoders/gamma'
import { VerificatumModPCrypto } from 'votejs/systems/verif'

class BaseScheme<M extends CryptoSystem<any, any>, E extends ChoiceEncoder>
  implements Scheme {
  constructor(public module: M, public encoder: E) {}
}

export class Cipher implements Ciphertext {
  constructor(public a: LargeInteger, public b: LargeInteger) {}
}

export class KeyPair {}

export class Zeus extends BaseScheme<VerificatumModPCrypto, GammaEncoder> {}

export { GammaEncoder }
