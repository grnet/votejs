import { ChoiceEncoder, Scheme, CryptoSystem, Ciphertext } from 'votejs/types'
import { GammaEncoder } from 'votejs/encoders/gamma'
import { VerificatumModPCrypto } from 'votejs/systems/verif'

class BaseScheme<M extends CryptoSystem<any, any>, E extends ChoiceEncoder>
  implements Scheme {
  constructor(public module: M, public encoder: E) {}
}

export class Cipher<E> implements Ciphertext<E> {
  constructor(public a: E, public b: E) {}
}

export class KeyPair {}

export class Zeus extends BaseScheme<VerificatumModPCrypto, GammaEncoder> {}

export { GammaEncoder }
