import { CryptoSystem, Ciphertext, PublicKey, PrivateKey } from 'votejs/types'
import { KeyPair, Cipher } from 'votejs/crypto'
import {
    ModPGroup,
    LargeInteger,
    PGroupElement,
    PFieldElement,
    PPGroup,
    PPGroupElement,
    ModPGroupElement, ECqPGroup, ECqPGroupElement
} from 'verificatum/arithm'
import { SHA256PRG, ElGamal, RandomDevice } from 'verificatum/crypto'
import { Hex } from 'verificatum/types'
import {ECP} from 'verificatum/arithm/ec';

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
  params: ModParams;
  group: ModPGroup;
  elgamal: ElGamal<ModPGroup, LargeInteger, ModPGroupElement>;
  source: SHA256PRG;
  statDist: number;
  device: RandomDevice;

  constructor(params: ModParams) {
    this.params = params;
    this.group = new ModPGroup(
      params.modulus,
      params.order,
      params.generator,
      1
    )
    this.statDist = 50;
    this.device = new RandomDevice();  // random source
    let seed = this.device.getBytes(SHA256PRG.seedLength);
    this.source = new SHA256PRG(); // ran
    this.source.setSeed(seed);
    this.elgamal = new ElGamal(true, this.group, this.source, 1);
  }

  prove(cipher: Ciphertext<ModPGroupElement>, random: Hex) {
    return true
  }

  generateKeypair() {
    return this.elgamal.gen()
  }

  encrypt(
    pk: PublicKey<ModPGroup, ModPGroupElement>,
    message: ModPGroupElement
  ): Ciphertext<ModPGroupElement> {
    const randomElement = this.group.pRing.randomElement(this.device, this.statDist);
    return this.elgamal.encrypt(pk, message, randomElement);
  }

  decrypt(sk: PrivateKey, cipher: Ciphertext<ModPGroupElement>): ModPGroupElement {
    return this.elgamal.decrypt(sk, cipher);
  }
}

export class VerificatumECqPCrypto
    implements CryptoSystem<ECqPGroup, ECqPGroupElement> {
    group: ECqPGroup;
    elgamal: ElGamal<ECqPGroup, ECP, ECqPGroupElement>;
    source: SHA256PRG;
    statDist: number;
    device: RandomDevice;

    constructor(group: ECqPGroup) {
        this.group = group;
        this.statDist = 50;
        this.device = new RandomDevice();
        let seed = this.device.getBytes(SHA256PRG.seedLength);
        this.source = new SHA256PRG();
        this.source.setSeed(seed);
        this.elgamal = new ElGamal(true, this.group, this.source, 1);
    }

    prove(cipher: Ciphertext<ECqPGroupElement>, random: Hex) {
        return true
    }

    generateKeypair() {
        return this.elgamal.gen()
    }

    encrypt(
        pk: PublicKey<ModPGroup, ModPGroupElement>,
        message: ECqPGroupElement
    ): Ciphertext<ECqPGroupElement> {
        const randomElement = this.group.pRing.randomElement(this.device, this.statDist);
        return this.elgamal.encrypt(pk, message, randomElement);
    }

    decrypt(sk: PrivateKey, cipher: Ciphertext<ECqPGroupElement>): ECqPGroupElement {
        return this.elgamal.decrypt(sk, cipher);
    }
}
