import { CryptoSystem, Ciphertext, PublicKey, PrivateKey } from 'votejs/types'
import { KeyPair, Cipher } from 'votejs/crypto'
import {
  ModPGroup,
  LargeInteger,
  PGroupElement,
  PFieldElement,
  PPGroup,
  PPGroupElement,
  ModPGroupElement
} from 'verificatum/arithm'
import { SHA256PRG, ElGamal, RandomDevice } from 'verificatum/crypto'
import { Hex } from 'verificatum/types'

class ElGamalKeyPair implements KeyPair {}

export class ModParams {
  constructor(
    public modulus: LargeInteger,
    public order: LargeInteger,
    public generator: LargeInteger
  ) {}
}

export class VerificatumModPCrypto
  implements CryptoSystem<ModPGroup, ModPGroupElement> {
  params: ModParams
  group: ModPGroup
  elgamal: ElGamal<ModPGroup, ModPGroupElement>
  source: SHA256PRG

  constructor(params: ModParams) {
    this.params = params
    this.group = new ModPGroup(
      params.modulus,
      params.order,
      params.generator,
      1
    )
    let device = new RandomDevice()
    let seed = device.getBytes(SHA256PRG.seedLength)
    this.source = new SHA256PRG()
    this.source.setSeed(seed)
    this.elgamal = new ElGamal(true, this.group, this.source, 1)
  }

  prove(cipher: Ciphertext, random: Hex) {
    return true
  }

  generateKeypair() {
    return this.elgamal.gen()
  }

  encrypt(
    key: PublicKey<ModPGroup, ModPGroupElement>,
    message: string
  ): Ciphertext {
    return new Cipher(new LargeInteger('ff'), new LargeInteger('ff'))
  }

  decrypt(priv: PrivateKey<ModPGroup, ModPGroupElement>, cipher: Ciphertext) {
    return 'message'
  }
}
