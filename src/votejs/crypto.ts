import { LargeInteger, ModPGroup } from 'verificatum/arithm'
import { Hex } from 'verificatum/types'
import {
  ChoiceEncoder,
  Scheme,
  CryptoSystem,
  Ciphertext,
  PrivateKey,
  PublicKey
} from 'votejs/types'
import { SHA256PRG, ElGamal } from 'verificatum/crypto'
import { GammaEncoder } from 'votejs/encoders/gamma'

class BaseScheme<M extends CryptoSystem, E extends ChoiceEncoder>
  implements Scheme {
  constructor(public module: M, public encoder: E) {}
}

export class Cipher implements Ciphertext {
  constructor(public a: LargeInteger, public b: LargeInteger) {}
}

export class ModParams {
  constructor(
    public modulus: LargeInteger,
    public order: LargeInteger,
    public generator: LargeInteger
  ) {}
}

export class VerificatumModPCrypto implements CryptoSystem {
  params: ModParams
  group: ModPGroup
  system: ElGamal
  source: SHA256PRG

  constructor(params: ModParams) {
    this.params = params
    this.group = new ModPGroup(
      params.modulus,
      params.order,
      params.generator,
      1
    )
    this.source = new SHA256PRG()
    this.system = new ElGamal(true, this.group, this.source, 1)
  }

  prove(cipher: Ciphertext, random: Hex) {
    return true
  }
  encrypt(key: PublicKey, message: string) {
    return new Cipher(new LargeInteger('ff'), new LargeInteger('ff'))
  }
  decrypt(secret: PrivateKey, cipher: Ciphertext) {
    return 'message'
  }
}

export class Zeus extends BaseScheme<VerificatumModPCrypto, GammaEncoder> {}

export { GammaEncoder }
