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
import { numbersHash, strbinToInt, proveDLog } from 'votejs/zeus/crypto/proofs'

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
        '29d4ac3efedd1eb90b3d7dbb0b3da101a0e0cae332aa12f253859202d56aad6005a78b955cd0b9b396984d5c398c18e8732723d07006ff9a94eb8a7982e7363c3301c4d09defaab08e90c38a3105c4ca34ffd18d24c4754d979631a2e3ca2c965d66f75d18eecd1fa125da488d2b9283e1d38919e6372a05d6d3d2d3e12046afd77e3a2c55811eee7175a9005b0ac9599c286eb28d74e3970ddb9e627c377df7ccddd7ea0a37876f0367e24c3cb6fbf05cfd465f0c2e0666018d300551c8ef2746690cc3da3dd2302a026da7f7a2610e784e210c1efc29d2389c273929e68238ec000e793a9209b256bcdd91e423c2dd2faa105e79614148c4c5c01fc7eceaa5'
    )
    let dlog = new LargeInteger(
        '20f6b9224512228c3accc0cb9a72872b0f942a6a01db574e15102fb8cb7b8c527e1ebc40df280b29d5dc81457c398f7dca5cf424bb9597dbedd524e5f27d86693b71d3e8f9282681c79debacf0a1b0cb3be423505d07c62d3a00e3b98bfbfc985068458278ca8004cd67c7c26be6811657911923e747b71f5eea19720886492f64aac4b44d6a357098590d8fdd3b26d5d367b8a1ae5842e2df7415bbc1cc466bbd1fb0c160a89faba2ca3426893615d57b0a5e24fe7709d121713375e91efb2c550c2fdf238fbf99b0d0dad4e1fbe7a14f10b616f57327c4e8f56f0d2a6b0836fc5d84362d13d1453668c03635b761f2533551cd01c9e368efa04be25f0ef6df'
    )
    let extra = [new LargeInteger(
        'b8072157b32829284e3cbfbad29b2f30207209d2c344e756bb61b2a07fbaceeda84dcaadfdf2885fb66305e05e9145c92e2ddfcc5ae619db7f9c7ad6c16a63af92c1520ff6df8615c70464d6d690f5f2f67f489adf0b65984c549766bdd1fd66bf0634becc68f8e4042c6f637767ca3542143f390de79861b052bdbc5f1509c0874b652b5fb09c73cfc775f536bab822168ebece4bc637f3f0f022a8cadf55bd0ca7ab94b2f9b1f4f542563987058677d51a761978b85f6e5148b0d64360a3fa8898d9a4bd63c01a989536051a2d15f7fe1e4c5caaec967878d2be7b7d4e24d1944058c354835b33831827eaf2a6c02d08942891a7b6fb37b1a3c974cde44b0'
    )]
    let randomness = new LargeInteger(
        '12a3c8453dda5b4fc3e60a4659434998b190b1e9e8125207c381c2cb2384d53e7a3cd12b7db6d305d7357133b510a1507af6c68d215117b07d3456f93f74a274ebd2fbce1cabbb56566f1bb7382700d3ae7b59a14d27786ef9e26c2972db27d321b7cf573952c206d9c430589ba2553549d8fddc9cdef76403259ece2232e8ed0bc5638adb3ac76a10d12611fac3311bd0273e99aea99eeda4cea42442333398ae134b60d6a1c1add10d5a80e5207ffa7f3299cfbca3fc9e10958e58d1158c4250a3030eddd0b07a8de65544e4ca70db4f46dc8fc843f6ca142998b48fb30fa124fbfef4c7613e71045161e564625e6aed733ae6254ae153ced1080f3329eb15'
    )
    let commitment = new LargeInteger(
        '361009d2e4ed7cc5bbcd88ec4082e7b2800bd82acdb8e854e8dc11dfb4dda8119719939a55dfacc00130392fa029a119c7de6b79778d2797957f493350f12289ee49f07f91ace47a87fbd2dbc6982607f5ae539f043e2d8dd2d60425e3b3d94fe0b65417e03f09cc38ac6970ab4402a7d411944904c57aeede537d3381008a0024a29f975250afe298f025022cd5c0267c5caff5886bb5157e14aca2b2bafdba553c68b8fa274cac518bf0c09cacd2564dcc838d6a68a48010ed31587c4d96b58a0790b89e95b4ad569d42c6618ea8fff349450bc47f0123b0753ee3ced5eac5eedfa2cbff27e24a155ef9566407c34eb3667206f86c0f5839a235097eb83f78'
    )
    let challenge = new LargeInteger(
        '50142b52f7f8b6772baba07a293b71a7a8a28071e1722bb65573a9dfe3067495d5370513b1c9ae27600a60175f07d3065a382e2307a426d61fce75c6c37816e91520692d508f54e2a0449f2f7fb31d4ac4da90532a4285c80afbb543270a6ccd76fe9aece9fc82cd74590652326ed3a9d2da869ea9d5b976fb9f1c92b1e007eacee046aeb3a0b55ce0f36be74315b957c4c71be3bd9234b8482ea27f5c98929b0485adebdadc057425fb1ff948ce77a89d6a25e44f62dc30f4b35436b1c340f30a17bf85547502880e57033a81a9c9e83d837d4e76dfc35bbebe9981e1bca8edc46f771ca07b431016128cdcc94e2e3ee9c6dedc631ba78cc909b54e18ae49dd'
    )
    let response = new LargeInteger(
        '3385fc3987182c3ac77543de41d4d92c0355248a5e6b6dda6745edc9289ae448bad3fd76c6bbf471772094ce93cf5fcc9cd5009ae36b7fb9351345d9bf81db27d6f15c1671854187d98aef54d34f757006adc3c7da0a480ec7a23cf6e17f8b9aae9d30baf5df42aa8013e4fa9511f01cf587b69f01a304687f909e6ceda2d87a15e0a8a6c228bdda4fadb4f0c53dc26cc956f05f27197d061cce9e45df0d8c86b90ea1d2d8dc7f88aca77e34da21c69a0374fadee3cc96e6b84b45b14e8b03cc65da8d3e7d533155c46b16543a9f73dccaf66c76e64d2149edaddac285386589a128440195d09230fc1a1ae169e1feb31fc17394966fc474d22f022fc316f932'
    )
    let group = new ModPGroup(modulus, order, generator, 1)
    let proof = proveDLog(group,power, dlog, extra, randomness)
    expect(proof.commitment.equals(commitment)).toBeTruthy()
    expect(proof.commitment.equals(challenge)).toBeTruthy()
    expect(proof.response.equals(response)).toBeTruthy()
  })
})
