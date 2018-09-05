import 'jest'
import { LargeInteger, ECqPGroup, ModPGroup } from 'verificatum/arithm'
import { arithm, convert, random } from 'votejs/util'
import { GammaEncoder } from 'votejs/encoders/gamma'
import { ZEUS_PARAMS } from './common'
import {
  VerificatumModPCrypto,
  ModParams,
  VerificatumECqPCrypto
} from 'votejs/systems/verif'
import { ECP } from 'verificatum/arithm/ec/index'
import { sha256 } from 'votejs/hash'
import { numbersHash, strbinToInt } from 'votejs/zeus/crypto/proofs'

describe('utils tests', () => {
  it('votejs arithm utils', () => {
    let a = new LargeInteger('ff')
    let b = new LargeInteger('00')
    expect(arithm.gt(a, b)).toEqual(true)
    expect(arithm.gt(b, a)).toEqual(false)
    expect(arithm.lt(b, a)).toEqual(true)
    expect(arithm.lt(a, b)).toEqual(false)

    expect(arithm.lte(a, a)).toEqual(true)
    expect(arithm.gte(a, a)).toEqual(true)

    expect(arithm.toNumber(a)).toEqual(255)
    expect(arithm.toLargeInteger(255).toHexString()).toEqual('ff')
  })
})

describe('gamma encoding', () => {
  it('should encode choices to integers', () => {
    let encoding = new GammaEncoder()

    let encoded = encoding.encode([1, 2], 2)
    expect(arithm.toNumber(encoded)).toEqual(6)
    encoded = encoding.encode([150, 10, 125], 300)
    expect(arithm.toNumber(encoded)).toEqual(13458406)

    let large = []
    for (let i = 0; i < 100; i += 1) {
      large[i] = i
    }
    encoded = encoding.encode(large, 300)
    expect(encoded.toHexString()).toEqual(
      '131cf3263a45182a2186f53a6beae088cc27ac4919969aaedf466760b2c30850705dff5d87f5e9324901382a6b3fd5a61fecfe506f5bbd117ad2c62ec5f555c24c2839038291ebfc1316817973c7ebe47ef1e252dd4d8dcd5ee8d6deec17671ad4db08'
    )

    encoded = encoding.encode([], 0)
    expect(arithm.toNumber(encoded)).toEqual(0)

    // test cached
    encoded = encoding.encode([1, 2], 2)
    expect(arithm.toNumber(encoded)).toEqual(6)
    encoded = encoding.encode([150, 10, 125], 300)
    expect(arithm.toNumber(encoded)).toEqual(13458406)
  })
})

describe('elgamal', () => {
  it('values should be integers', () => {
    let { modulus, order, generator } = ZEUS_PARAMS
    let params = new ModParams(modulus, order, generator)
    let vrf = new VerificatumModPCrypto(params)
    let keypair = vrf.generateKeypair()
    expect(keypair[0].values[0].value).toBeInstanceOf(LargeInteger)
    expect(keypair[1].value).toBeInstanceOf(LargeInteger)
  })
})

describe('elgamal elliptic curves', () => {
  it('values should be ECP', () => {
    let ecGroup = new ECqPGroup('P-224')
    let vrf = new VerificatumECqPCrypto(ecGroup)
    let keypair = vrf.generateKeypair()
    expect(keypair[0].values[0].value).toBeInstanceOf(ECP)
    expect(keypair[1].value).toBeInstanceOf(LargeInteger)
  })
})

describe('votejs encryption decryption test ModPGroup', () => {
  it('message should be equal to decrypted message', () => {
    let { modulus, order, generator } = ZEUS_PARAMS
    let params = new ModParams(modulus, order, generator)
    let vrf = new VerificatumModPCrypto(params)
    let keypair = vrf.generateKeypair()
    const m = vrf.group.randomElement(vrf.device, vrf.statDist)
    const cipher = vrf.encrypt(keypair[0], m)
    const decryptedM = vrf.decrypt(keypair[1], cipher)
    expect(decryptedM.equals(m)).toBeTruthy()
  })
})

describe('votejs encryption decryption test ECqPGroup', () => {
  it('message should be equal to decrypted message', () => {
    let ecGroup = new ECqPGroup('P-224')
    let vrf = new VerificatumECqPCrypto(ecGroup)
    let keypair = vrf.generateKeypair()
    const m = vrf.group.randomElement(vrf.device, vrf.statDist)
    const cipher = vrf.encrypt(keypair[0], m)
    const decryptedM = vrf.decrypt(keypair[1], cipher)
    expect(decryptedM.equals(m)).toBeTruthy()
  })
})

describe('util convert methods test ModPGroup', () => {
  it('keys should be equals', () => {
    let { modulus, order, generator } = ZEUS_PARAMS
    let params = new ModParams(modulus, order, generator)
    let vrf = new VerificatumModPCrypto(params)
    let keypair = vrf.generateKeypair()
    let pkHex = convert.pkToHexModP(keypair[0])
    let skHex = convert.skToHex(keypair[1])
    let pk = convert.pkFromHexModP(pkHex, vrf.group)
    let sk = convert.skFromHex(skHex, vrf.group)
    expect(pk).toEqual(keypair[0])
    expect(sk).toEqual(keypair[1])
  })
})

describe('util convert methods test ECqPGroup', () => {
  it('keys should be equals', () => {
    let ecGroup = new ECqPGroup('P-224')
    let vrf = new VerificatumECqPCrypto(ecGroup)
    let keypair = vrf.generateKeypair()
    let pkHex = convert.pkToHexECqP(keypair[0])
    let skHex = convert.skToHex(keypair[1])
    let pk = convert.pkFromHexECqP(pkHex, vrf.group)
    let sk = convert.skFromHex(skHex, vrf.group)
    expect(pk).toEqual(keypair[0])
    expect(sk).toEqual(keypair[1])
  })
})

describe('util cipher serializer -- deserialize test ModPGroup', () => {
  it('ciphers must be equals', () => {
    let { modulus, order, generator } = ZEUS_PARAMS
    let params = new ModParams(modulus, order, generator)
    let vrf = new VerificatumModPCrypto(params)
    let keypair = vrf.generateKeypair()
    let m = vrf.group.randomElement(vrf.device, vrf.statDist)
    let cipher = vrf.encrypt(keypair[0], m)
    let serializedCipher = convert.serializeModPCipher(cipher)
    let deserializedCipher = convert.deserializeModPCipher(
      vrf.group,
      serializedCipher
    )
    expect(cipher.equals(deserializedCipher)).toBeTruthy()
  })
})

describe('util cipher serializer -- deserialize test ECqPGroup', () => {
  it('ciphers must be equals', () => {
    let ecGroup = new ECqPGroup('P-224')
    let vrf = new VerificatumECqPCrypto(ecGroup)
    let keypair = vrf.generateKeypair()
    let m = vrf.group.randomElement(vrf.device, vrf.statDist)
    let cipher = vrf.encrypt(keypair[0], m)
    let curve = keypair[0].values[0].pGroup.curve
    let serializedCipher = convert.serializeECqPCipher(curve, cipher)
    let deserializedCipher = convert.deserializeECqPCipher(
      vrf.group,
      serializedCipher
    )
    expect(cipher.equals(deserializedCipher)).toBeTruthy()
  })
})

describe('sha256', () => {
  it('returns expected results', () => {
    let hash1 = sha256(['a', 'b', 'c'])
    expect(hash1).toEqual(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    )
    expect(sha256(['abc'])).toEqual(hash1)
  })
})

describe('random source dummy test', () => {
  it('returns a random LargeInteger', () => {
    let { modulus, order, generator } = ZEUS_PARAMS
    let group = new ModPGroup(modulus, order, generator, 1)
    let r = random.getRandomInt(LargeInteger.ONE, group.getElementOrder())
    expect(true).toBeTruthy()
  })
})

describe('numbersHash and strbinToInt Functions tests', () => {
  it('check hash and Integer', () => {
    let elements = [
      new LargeInteger(
        '9decdda7acdef3b3b7f2742887635785a12a3ce10183ffe882573830b28b7939e3feec0c2a850b88e96754ee46edf4b858b19c9587a7a29e72d6c4583478d4ee377a6111eb2a651d8ef9994c2fbb7a2343ec3fa7ef16317ebacd64d8cbd7ebdf3f68e7f63e606854aa609538a25818b8b661032e3ce8c5a1657d82e90d2249d3af079e7de9bf37e0911d6a9d396e2dda3a7793f0ba5ce0beb1f70fc1b5c8726805471028e176fb6ec4f9ce590e4a4506584248157ec44c36fd35d73871efbd8cf59d22dbeda34acb008dc303b1252c428fc6b8231f1bfdba3119e9743ea6f43ace51e347e13d18b1f5fd54c2846781a85290450ef9e37503d30d03315d569c73'
      ),
      new LargeInteger(
        '97d518e0f381ba1a990d70e4349d2affa2663fa85bde092507b827113607767053fe01f3432f1aa976824f1e8990ceb2349c5cb124535c0a0b32f65ab9009e95f4012820178483644b282134666ca71e62eaadeb8b80cccd0a690feca69c292036d6c2ab642e4a6ddc529ca687e16c48492e470ee82de4622235e5dd511eb86162fc700e53da42f27ddf640d4f15de7bf34bbd4107531f8448c2e1dca378e553801152ba96b5bb0fb716575a8c0a88b13ea74b53816a13fad7d1c1c6a822793922fe0eefc78463bea9465d745ba5ee35f1e72b95a076c20f6bbf26e93f8a8974db253f8d6519cb61474ffba95f2c749f1ccf93562983306437ac492dc22f8d77'
      ),
      new LargeInteger(
        '4ef66ed3d66f79d9dbf93a1443b1abc2d0951e7080c1fff4412b9c185945bc9cf1ff7606154285c474b3aa772376fa5c2c58ce4ac3d3d14f396b622c1a3c6a771bbd3088f595328ec77ccca617ddbd11a1f61fd3f78b18bf5d66b26c65ebf5ef9fb473fb1f30342a55304a9c512c0c5c5b3081971e7462d0b2bec174869124e9d783cf3ef4df9bf0488eb54e9cb716ed1d3bc9f85d2e705f58fb87e0dae4393402a3881470bb7db7627ce72c872522832c21240abf62261b7e9aeb9c38f7dec67ace916df6d1a5658046e181d892962147e35c118f8dfedd188cf4ba1f537a1d6728f1a3f09e8c58fafeaa614233c0d4294822877cf1ba81e9868198aeab4e39'
      ),
      new LargeInteger(
        '6f7badc5f0714bd75ab7c937d537b10fcf240106c8d728298b25e5ff43f4a6407880943aac7da307f5a70a53ac7f1d8516d1a114df625fb0b6b6b8de764ab9d228304701eb1771eebfccdaedb91b83a43792bf13b170ba3e791e293df99b6688710dc1fa1c168c96fd5bf42a28bd75e68ea9572860db46b573bd21e9428fd83b51a2f239253f3ec3343ceec497c9846d5c4060e54f2e8fc9a144de4e4ce986195b4e9f10026aec6960148e31a04caa50b2b0be6f045b7be694dc7386a9d303a35e2ff51cd3355442b48b70d1f6557cbaec353af316bc05e015f97cf7d5fb55ca6c02a709547ca7208c0a08b7feaaf211619f91c274c139da3ca73c923250ccf4'
      ),
      new LargeInteger(
        '95b7d3b4b4a4ab9b47dadbfba239268a5d329726bb6090a13a0487161db1bb6e59c5310574e99524c656fa38ff22834db090588c4c2e1aa3744dca4267c3fdadb659fe7b6043f2d8ba0e35d1b223ec9074cef287b2b1ca1dc933dd44b6e71a6335870ae426ebb889401c489fc240d5b2a886e27bafdd4314a2188e2efa03857a166184584e64a634576c96f1e69bde4378e1de47366fd815c3446bf8e465a140d0134c5d40f43d79fbaeb8b518d8a90d15c3f9f532f7e02949042cbe5f00178418ab05e3de465eaebb4288f18dbc6125ab3b643f49e8f7498c5965c4f054713cc9ec913ae01fff23321de6b9ea9a5ccf8caeb1685ba961bace6e079c326742f6'
      ),
      new LargeInteger(
        '7327443c8e0c1f3be833a8768af5bba9c1e2e398d8b8367c7079a475d8779b330a1244f082e06303ea0d91713fb173c62aab15bebca8b3389ac2da86b7ab63ad5a7e4d20992f12d27ea7f1430f4d8f7f1894e151a044ddbfed4bd51a173e7d6ad211aa70680e1768f929d1be3919cc05fef14653b590e230a79ad42662d4ceb0aa963fea81ef769574e31a0d9d84838d3b45156eaba6913f8d76b99af8718a493e8b01b19316f60ba4b624cadeac51aa9c495b69afd1386c96da145f444d7241af182d5034c5023f75982e5db43d9ccf727fe8e7f02128978095aa966c4a57c6470319a2e1314afdddb9025fd9d5cf2752864bdd07f3c0fbd83f47307b96862b'
      )
    ]
    let numbersHashValue = numbersHash(elements)
    expect(numbersHashValue).toEqual(
      '1a960bc7098142c07da1f95278b113bead09888c35d74a46084e996e9f36d465'
    )

    let nullHash = numbersHash([])
    expect(nullHash).toEqual(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )

    let intFromHash = strbinToInt(
      '1a960bc7098142c07da1f95278b113bead09888c35d74a46084e996e9f36d465'
    )
    expect(arithm.toNumber(intFromHash)).toEqual(
      2786924798350076817666911618935206501410946445904683296534842589082013875160780941375600631394186637644647950256162555449647965399767680916580309237588273
    )

    let intNull = strbinToInt('')
    expect(arithm.toNumber(intNull)).toEqual(0)

    let intZeroHash = strbinToInt('0')
    expect(arithm.toNumber(intZeroHash)).toEqual(48)
  })
})

describe('getRandomInt test', () => {
  it('check if random numbers are in a specific set of values', () => {
    // corner case of zero
    let sum = LargeInteger.ZERO
    for (let i = 0; i < 1000; i++) {
      sum.add(random.getRandomInt(LargeInteger.ZERO, LargeInteger.ONE))
    }
    expect(sum.equals(LargeInteger.ZERO)).toBeTruthy()
  })
})
