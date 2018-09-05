import { ChoiceEncoder, Scheme, CryptoSystem } from 'votejs/types'
import { GammaEncoder } from 'votejs/encoders/gamma'
import { VerificatumModPCrypto } from 'votejs/systems/verif'

class BaseScheme<M extends CryptoSystem<any, any>, E extends ChoiceEncoder>
  implements Scheme {
  constructor(public module: M, public encoder: E) {}
}

export class KeyPair {}

export class Zeus extends BaseScheme<VerificatumModPCrypto, GammaEncoder> {}

export { GammaEncoder }
