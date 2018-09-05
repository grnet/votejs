import { CryptoSystem, Ciphertext, PublicKey, PrivateKey } from 'votejs/types'
// import { KeyPair } from 'votejs/crypto'
import { ModPGroup, LargeInteger, ModPGroupElement } from 'verificatum/arithm'
import { SHA256PRG, ElGamal, RandomDevice } from 'verificatum/crypto'
import { Hex } from 'verificatum/types'

// class ElGamalKeyPair implements KeyPair {}

export class ModParams {
  constructor(
    public modulus: LargeInteger,
    public order: LargeInteger,
    public generator: LargeInteger
  ) {}
}

export class VerificatumModPCrypto
  implements CryptoSystem<ModPGroup, ModPGroupElement> {
  group: ModPGroup
  elgamal: ElGamal<ModPGroup, LargeInteger, ModPGroupElement>
  source: SHA256PRG
  statDist: number
  device: RandomDevice

  constructor(group: ModPGroup) {
    this.group = group
    this.statDist = 50
    this.device = new RandomDevice() // random source
    let seed = this.device.getBytes(SHA256PRG.seedLength)
    this.source = new SHA256PRG() // ran
    this.source.setSeed(seed)
    this.elgamal = new ElGamal(true, this.group, this.source, 1)
  }

  prove(cipher: Ciphertext<ModPGroup, ModPGroupElement>, random: Hex) {
    return true
  }

  generateKeypair() {
    return this.elgamal.gen()
  }

  encrypt(
    pk: PublicKey<ModPGroup, ModPGroupElement>,
    message: ModPGroupElement
  ): Ciphertext<ModPGroup, ModPGroupElement> {
    const randomElement = this.group.pRing.randomElement(
      this.device,
      this.statDist
    )
    return this.elgamal.encrypt(pk, message, randomElement)
  }

  decrypt(
    sk: PrivateKey,
    cipher: Ciphertext<ModPGroup, ModPGroupElement>
  ): ModPGroupElement {
    return this.elgamal.decrypt(sk, cipher)
  }
}
