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
import { numbersHash, strbinToInt, proveDLog, proveDDHTuple } from 'votejs/zeus/crypto/proofs'

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
    expect(pk).toEqual(keypair[0]) // FIXME change toEqual with toBeTruthy
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
    expect(pk.equals(keypair[0])).toBeTruthy
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

describe('proveDLog test', () => {
  it('check if returns values are equals to zeus prove_dlog function', () => {
    let modulus = new LargeInteger(
      '9decdda7acdef3b3b7f2742887635785a12a3ce10183ffe882573830b28b7939e3feec0c2a850b88e96754ee46edf4b858b19c9587a7a29e72d6c4583478d4ee377a6111eb2a651d8ef9994c2fbb7a2343ec3fa7ef16317ebacd64d8cbd7ebdf3f68e7f63e606854aa609538a25818b8b661032e3ce8c5a1657d82e90d2249d3af079e7de9bf37e0911d6a9d396e2dda3a7793f0ba5ce0beb1f70fc1b5c8726805471028e176fb6ec4f9ce590e4a4506584248157ec44c36fd35d73871efbd8cf59d22dbeda34acb008dc303b1252c428fc6b8231f1bfdba3119e9743ea6f43ace51e347e13d18b1f5fd54c2846781a85290450ef9e37503d30d03315d569c73'
    )
    let generator = new LargeInteger(
      '97d518e0f381ba1a990d70e4349d2affa2663fa85bde092507b827113607767053fe01f3432f1aa976824f1e8990ceb2349c5cb124535c0a0b32f65ab9009e95f4012820178483644b282134666ca71e62eaadeb8b80cccd0a690feca69c292036d6c2ab642e4a6ddc529ca687e16c48492e470ee82de4622235e5dd511eb86162fc700e53da42f27ddf640d4f15de7bf34bbd4107531f8448c2e1dca378e553801152ba96b5bb0fb716575a8c0a88b13ea74b53816a13fad7d1c1c6a822793922fe0eefc78463bea9465d745ba5ee35f1e72b95a076c20f6bbf26e93f8a8974db253f8d6519cb61474ffba95f2c749f1ccf93562983306437ac492dc22f8d77'
    )
    let order = new LargeInteger(
      '4ef66ed3d66f79d9dbf93a1443b1abc2d0951e7080c1fff4412b9c185945bc9cf1ff7606154285c474b3aa772376fa5c2c58ce4ac3d3d14f396b622c1a3c6a771bbd3088f595328ec77ccca617ddbd11a1f61fd3f78b18bf5d66b26c65ebf5ef9fb473fb1f30342a55304a9c512c0c5c5b3081971e7462d0b2bec174869124e9d783cf3ef4df9bf0488eb54e9cb716ed1d3bc9f85d2e705f58fb87e0dae4393402a3881470bb7db7627ce72c872522832c21240abf62261b7e9aeb9c38f7dec67ace916df6d1a5658046e181d892962147e35c118f8dfedd188cf4ba1f537a1d6728f1a3f09e8c58fafeaa614233c0d4294822877cf1ba81e9868198aeab4e39'
    )
    let power = new LargeInteger(
      '64a29ef910d5e3ed9fc696198472f4c468120f4a8b4cae7e8a9b5e9af676752567d232d93c619199ea5003170a35bf939daafd2e57a193b7126d94e94d3c561262e2d5de7a00797e8ec6201555e4c4ab0abcd2b5f16decad33fa526ec3b869d178a00ba9ab8505c7748956b30715f2714c97461451e905ccc84197d9b28f6e9c1b75d23b5df4c5cb214b76aa2f0cccaa582f5cf00c1e626e642cb1c5d9602c557861252c53d3f90c5478d9948ec4f0b795d1ea99c932de12c67d07d00c5028ce03e445c8d8884a56483a322b01cf250ad605cb18ca28bfb9f828ecdb79daa83645a88c3dfe3bf43e1f16c18ac2fa107361029cbb5662095b458cfcbc13b23919'
    )
    let dlog = new LargeInteger(
        '28366eeacb2ea701ae5ec669ed21119389702730319ba6fb5f7c48d2879bec62008c63360690bf6245eef8986e9fbc827771520afdcd0a4791599ab3d3735d1f83ae47e0761227490d9e0a746d9e6b06633191a91a1d5bc0e1facf1ca62e803f44d65dd096dd18e2ae5dfccccfa332bc74ac47605cddbd98a1598ff11c7e254aebd21d725fda27c7ef985dbca92e9649f8fab41fb9d08b6ee4ed12c77da38f38cdc750f720cf8b956d7d6f8a048d93831ac67cfea65d57e496c8d5f76599ce34f55fa303696338e0bad2a60879060d01a6a302feca3fabfebf1fd42dc9ef10fe3a4f68dfc3f3b33382935df8e78704ef63fbd175481096b78adf1d9b65e0fbac'
    )
    let extra = [new LargeInteger(
        '823663e74ca985e03a7717af1215811a086ab83a89d8af55dcaa6597e568058f93706be1b8680514d44e0a7387b494eb9478e5e068dda23534743d1c478047242fcea7aa5c57b68cf87202e42d4615efb60376846ae4674b82513f9963bace955f214fdbd8213dfdfad58ea3dd7493a98b0c7be3c4662151b643cc94fabd9172f761f870edf2452cc848f97783763ae0cd6e77f633af2a9f5d41badcb85166dfb15651e3f71799c56fe68fea4e1d0fb176ffab152edafec1da287762206e8aea58e60ef60e095863c604a3fed9b4dd07a5d93e1f303112d25f172a58d5f8834295b74a3cc0f95e936aa45943edc6cfc92d9a0608319b9d3b98021bba7503fdcf'
    )]
    let randomness = new LargeInteger(
        '26365f3ee4491b5e20d89e6b5ed5e244ea6d3e924b4a3dceea4a9a77bfd0c8d2c8489eee762ed281b5b944810d26a4a65fda0ebf6b5a1ccd9d7fa4fb2a0504b05066560848f088363fa24e0cb3cfa44f11807037dada04d87410723a1fe95304f54157422f4027742346facecb52748ddba939d794aeb9fae67cb73f7cdf841c353a906ccc98c6ea6f022b549ecb37f220c0a25d0d412d613c93e7be79aef27031520ac8b79d1f9d8d97e8550ab8bcd304502ac64d23648c16124d2804bc1378984a42872fbdb4b684c37c7aa59c2cbd33c781301501bb491d4eed71cd6ccbb57d8de2da485ea525cdbdd58b78123d7399e0a4dd709d3138e433c71edc27d631'
    )
    let commitment = new LargeInteger(
        '5400120611d97152a8054dbec42c5929b53f148f88101558fd9dc8aaf8d1b7c28d2a723e90bba8aecf0a06a9e84775a91e2a46b4c4d1a46724cbf74ea70d98459887432148a0bee29d853137a50e6370b9450e7af8a63a9fa3f717066cd903b8f193e9a1808f1799b879d86d67822a879a651cb30b6ea8b97a4433349411b7a41665e6e74afb6b291c0babaed39a429e448725a7e5abf9c4822d3c2a7f2672189ea835c31b3749489987ddc70b9ce8af39c794fe3081d23d3207cf79ffcdca83cc550c2aa1bad3cdd9067877300adedad94bbaba3fe01571afaa616f1a084d6d5bad21be8a682037476c4e6029c7dcbb5bcab440dd8bb452904bac369ff6de9b'
    )
    let challenge = new LargeInteger(
        '55561115cdbe32e351b0997a61ec374a5d0bd21b5fb17d26d35cd529ea3db5fa97efed3ae369c10f9e658778b8c91995f2e3203dcd7c030a3542c7362d56ef0df72d84baaa39fcc3ffaae9ef5f08abc7cffb1e651b84abc30b062579771530e562d7cf8c54dae6d9f0bf5d21570a7c62126dc723546efdea6a626fa09dac9b006cc250e5b96f71bbffcc60655e4afa8b95539c39670afa3870b8036b5f18964d2cc9205fe225c961677e4f07d08ab21afdfa7378c7c942f7f77928082be711d824b1d70f8a3383a32ec4de3ad25f074d8af0485f5d173d292e865f5f3e4627618da7775840eae3799477491f12b7f0954ba8f318af412c43b4403d3af54d723d'
    )
    let response = new LargeInteger(
        '1dd60b341e4dfc5096e971cbc5293325232fdcf467b3e1c32017786cc60c752435daacc54c54fa87632edfbf953c95d75e4cd7a3ad445ecb120450ecf5e47f10df505eed11d90f2ffc00922122f2804cad63ba2a386342a378d143ff7c846229d170b8d131a35b3402058fa44174eab0c64b09aeff2a73f231c9d6af348bec1817b556ec8ea44a66adfc029c9cefbe1b0ce429b510c6ab326f8aa7d50a60706dbe02d10d5029d71016b67519551b945a4e451ac8381c57d7f6e55c118d00a79d6b9fdafef9795c09fa9ddb3dcf311e216d4d33e5e72a9c6af9a92a147a780aefde633684ded51050afb4b9448ba0f4b69e32bc4362f1a5228c8e9260deb65415'
    )
    let group = new ModPGroup(modulus, order, generator, 1)
    let proof = proveDLog(group,power, dlog, extra, randomness)
    expect(proof.commitment.equals(commitment)).toBeTruthy()
    expect(proof.challenge.equals(challenge)).toBeTruthy()
    expect(proof.response.equals(response)).toBeTruthy()
  })
})

describe('proveDDHTuple test', () => {
    it('check if returns values are equals to zeus prove_dhh_tuple function', () => {
      let modulus = new LargeInteger(
        '9decdda7acdef3b3b7f2742887635785a12a3ce10183ffe882573830b28b7939e3feec0c2a850b88e96754ee46edf4b858b19c9587a7a29e72d6c4583478d4ee377a6111eb2a651d8ef9994c2fbb7a2343ec3fa7ef16317ebacd64d8cbd7ebdf3f68e7f63e606854aa609538a25818b8b661032e3ce8c5a1657d82e90d2249d3af079e7de9bf37e0911d6a9d396e2dda3a7793f0ba5ce0beb1f70fc1b5c8726805471028e176fb6ec4f9ce590e4a4506584248157ec44c36fd35d73871efbd8cf59d22dbeda34acb008dc303b1252c428fc6b8231f1bfdba3119e9743ea6f43ace51e347e13d18b1f5fd54c2846781a85290450ef9e37503d30d03315d569c73'
      )
      let generator = new LargeInteger(
        '97d518e0f381ba1a990d70e4349d2affa2663fa85bde092507b827113607767053fe01f3432f1aa976824f1e8990ceb2349c5cb124535c0a0b32f65ab9009e95f4012820178483644b282134666ca71e62eaadeb8b80cccd0a690feca69c292036d6c2ab642e4a6ddc529ca687e16c48492e470ee82de4622235e5dd511eb86162fc700e53da42f27ddf640d4f15de7bf34bbd4107531f8448c2e1dca378e553801152ba96b5bb0fb716575a8c0a88b13ea74b53816a13fad7d1c1c6a822793922fe0eefc78463bea9465d745ba5ee35f1e72b95a076c20f6bbf26e93f8a8974db253f8d6519cb61474ffba95f2c749f1ccf93562983306437ac492dc22f8d77'
      )
      let order = new LargeInteger(
        '4ef66ed3d66f79d9dbf93a1443b1abc2d0951e7080c1fff4412b9c185945bc9cf1ff7606154285c474b3aa772376fa5c2c58ce4ac3d3d14f396b622c1a3c6a771bbd3088f595328ec77ccca617ddbd11a1f61fd3f78b18bf5d66b26c65ebf5ef9fb473fb1f30342a55304a9c512c0c5c5b3081971e7462d0b2bec174869124e9d783cf3ef4df9bf0488eb54e9cb716ed1d3bc9f85d2e705f58fb87e0dae4393402a3881470bb7db7627ce72c872522832c21240abf62261b7e9aeb9c38f7dec67ace916df6d1a5658046e181d892962147e35c118f8dfedd188cf4ba1f537a1d6728f1a3f09e8c58fafeaa614233c0d4294822877cf1ba81e9868198aeab4e39'
      )
      let message = new LargeInteger(
        '794803ff4f330b220879e42d606736c61751359526b84e7e220986e64fd7cf6b3a847bbdab35c46ed6eec760995a884e3636d49be159361a97c83a234e0b22f87a01877677a47bdbd5f9bfdd94c372952ec5337a277842ea22f445916d37cb886d1f51b5822166f1a12ad3cb9dbf8851319434908d93af1772eb91f47261ce1bfbb5f3ada4d6d04934ae16a84a7bbe8858861da77311480c5364870ef728568e28b0757cd81f4e7722142841dee84b394c47b7117787252baa63b601a737ec5583737c4ae01468c5f74b2d512dccffa4c778e37c444d1780e712cce64de9b1c39e27a94304fb7b9f437ec22915370b5b637e3e4d5ab6735056fb64da9636b530'
      )
      let basePower = new LargeInteger(
          '4017702350d8af226aa8e666c39506d6643e7460dc010395cb908c913ab8d2e7ccb9f6b085a10dc9efd78fdd8bbec280fe7f0155f2421c9eccb211f4d4a9a31b5a03794e1867a7f8d06571d41f25b72dda542e1e01589caf3f56314697215bdaf19098f98333f9266672218b9e69d1d5969348b26554333355c07d1582d233a0aede283533ccde9e0a9d74e9bf839bf34491cb9e8c8fa4c663b9d5f27b3790f38c6b121cff29f6c9c897da875ae590bb0cdbda770c1b0975ca4a4b5edf07449f022147f76825c9fba35ef27cdff898ddacfad86072c5300f73f3fdae133151027daf50d4dd2e1d6c75de9677dcd8e10971b342d8794188882ef53267446584ef'
      )
      let messagePower = new LargeInteger(
          'c4a33411ec181969c42e55b5ef34278221b1d5c40c82037ce6600c4748fffd4f4a5d38cf54ba4ded1bc5011c8a9071298edbdc6fa6ccfb2cf5f13b6259225f60e585f508f5558aa159ed39c948956dffdd9cf081e0e43be9ff7de224fc05a3a14e7a262b3bd6404f8dd82b4bf5fe8351fdda360cd110ad0ab2a39f7b515a85114ed10db36b5b8f79def6c949aff9519ee27fa520010f1f715a1ded7ed24d86afdd3a08bd05538df1d41c0d2ca16af8636e7a0c1d3f3941215a2d910ea9bb1aada3192e9a9c972417abd674525a9ac486f096c21d48d1ca0d4cb45abd84bf3845915d3a19365c2d61ffd1366f2dd6eb14111f0b9ceaaeb305dd6c6a749b9c9e6'
      )
      let exponent = new LargeInteger(
          '39524f693c435d5eb1af53e278097943fe01db67b66ad3becd01fef9ad07ba4744c9990234e049e21b8d598cf288deaa4fd38b5f3e7fddcb25ee4a47f62b12d511feca69629775dc26d2817e3da694dacdb32673d24c2629b7d537b18d620bbadbeb8f4ea8b881a886c0389d92e429c77fd390bb6d45c6b4a1fb85f30475e30c5a2db6cf7c8f7188123f063e01dd9d9fd948fd6bdbfac70895d92a025d6a822c7b322b3f41a69742d37685907269be83d310dba1a75748f131989c67ed695027619def664e7f3df86be73bc8e1bc70950ace2e8cec11991af5ae33a9db90a774cee9fc187845c9cdbb692734e29c3b3cd3e7a120b33fe6bb698d6ce9668b703e'
      )
      let randomness = new LargeInteger(
          '2161d9939d7f29ea4423e8b92a93951b7de37c36579664ea73b410d6e540ab0313240053947c454121862be33aa5e752fed6846b100bef6adc48679dc8c9b6ded4596fcbb5de35d5237474f7a4a450e20425c04a1c988e8e4a74e8db37d4b9a8acc7e5c8ad987dc50de3269e337514b2005282aeef7a9c1663fcd25a98ceba7e14f93d8709ff9dc95c2e0ecdeecfea77eb9b71ea524022df3193113b211e03a517462a17c73925866c0b100e01160fc410836f78aba4bd6c04dafd37f5b318f6a28d3f27436061c8bcd54e7e16afe329c6195fae6ed7bf1ff249b3ea0c4d1054440528720316a2feafa3e4ff5b1518cdcc3c9f2916ab99d6b90b8d08910418c2'
      )
      let baseCommitment = new LargeInteger(
          '43b9afc4a9021378c7a7abf78284685765ba1c72207953dd56d680faab2ac327e4996af68507072d1229d70e6caa9d92debfa34528044db383b5dbf274c1f9d60b370d46bc4300b8febf85215e57aec92be1edf6bd5b0ca8cf7577c54cb8af2d4f628bb3d274a6ed75ac416858a770fed04368bd14a205e4c16e34782a2f9ffa85bedcfd70fdfb45f0d523b2131f23f88a14964b204a4dd3e1a26442345aa79f09d37fc98c4a806dece261358150a0e6aeaa965b6ff389bd95ada74f19efa704e6f1397addfd924c86597e445be7093d18a04524b6a6324a4e64ce331160d7069370a6431ab944aa49ac1603139f80ba48f708652d3ce00ba89ad89384022039'
      )
      let messageCommitment = new LargeInteger(
          '872a2441b4c4023e85765c50c38c0130e92da1c0ba0a22f7beb2b267397480ac3c972752c2bbf710fc2576d670f56c7aa55250a0ff193cbc0e0e5f5cafa1aaf1d4ada149c5a1f005decbedd2b0cbf521f7fe86b46478a264b6adce06116bdb819891823ceb1958a3f5ec3eae8f479714fc153c11a9048ceaefb85aad9ee3206ce1d6ada55bcc8e6d608aea1b7034b8fd65364a8758c35461e061366a46829671b401fe0a6afe197d85a2fd8fa88d8df32105963b93adb59f68c5f7ef3e9e6299c4bc3c50734aef16770ce09b9b04754f37d5ed5de3274958dc839e17f131cb240ca520d7f918cc8a33e9210d2a8150901bd7dd8759109e0c040cf1620e45ee3e'
      )
      let challenge = new LargeInteger(
          '8aa6ed4c8359987804271c86e062ee42b0420c4d34c5466ae86a6da7019183d3cf22987bf2d2a989430626d5f6c8e613a399a5b5c271d92e7c3972326e27e08c7347c02bd0647d2067fdbacd2523832a0e7fd12196778eb301188a5188677b2991273e17ae29bb92e6d5732d0f7a16bd373b3f0c37158981a7824b7dbb283c3ed6fdba0ac40e2da97799021bc78f898348c2a867289590af7ee72db78145c6b859a092d70f3587bc0157684d0399822b38e56aab5bea8c7c0f6e4ffab9ddc65bf76671d44fdd3830a07a58f324a7e760dd16a8c54a67531e229e20acff46c895a6261b5e489bb8fcc20a324fdefdb0504027bd8bfa0312c2c7e7b8503ff66e82'
      )
      let response = new LargeInteger(
          '10ace07e08cd914cb198a8b7a244104163a245905b8455db0fead25f9f4eb95d688060362b9f8fb61dbb7dc21d889da2b4ac747cb622e432ada8adb1057edae5943662a290f038d962b5cb1513fd3fa43cee35757f847e258ade7c30fca3b9131013f81d2e1dd1ed700e846f586b72abaffd1b34bba97d9e005bbe97561ec2a33aebc60f3c46dd8046f5e2e71e1fffaf6346339c456b4d85f9b1967cbe5558b4c60068df44edebd4309462ad64ff86db3f31c8fe3d945ea723678de64117c8f36ff434f5ec7bd11d7f72f11c292c64f2a408a9761dc24bcebf78b59af9a70ad6a13c39c567afaa227707dcb2f0a4773dcdcda46ac9b2fa8eb0854f15f5cfa565'
      )
      let group = new ModPGroup(modulus, order, generator, 1)
      let proof = proveDDHTuple(group, message, basePower, messagePower, exponent, randomness)
      expect(proof.baseCommitment.equals(baseCommitment)).toBeTruthy()
      expect(proof.messageCommitment.equals(messageCommitment)).toBeTruthy()
      expect(proof.challenge.equals(challenge)).toBeTruthy()
      expect(proof.response.equals(response)).toBeTruthy()
    })
  })