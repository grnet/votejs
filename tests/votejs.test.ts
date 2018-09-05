import 'jest'
import { LargeInteger } from 'verificatum/arithm'
import { arithm, convert, random } from 'votejs/util'
import { ZEUS_GROUP } from './common'
import { VerificatumModPCrypto, ModParams } from 'votejs/systems/verif'
import { sha256 } from 'votejs/hash'
import {
  numbersHash,
  strbinToInt,
  proveDLog,
  proveDDHTuple
} from 'votejs/zeus/crypto/proofs'

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

describe('elgamal', () => {
  it('values should be integers', () => {
    let vrf = new VerificatumModPCrypto(ZEUS_GROUP)
    let keypair = vrf.generateKeypair()
    expect(keypair[0].values[0].value).toBeInstanceOf(LargeInteger)
    expect(keypair[1].value).toBeInstanceOf(LargeInteger)
  })
})

describe('votejs encryption decryption test ModPGroup', () => {
  it('message should be equal to decrypted message', () => {
    let vrf = new VerificatumModPCrypto(ZEUS_GROUP)
    let keypair = vrf.generateKeypair()
    const m = vrf.group.randomElement(vrf.device, vrf.statDist)
    const cipher = vrf.encrypt(keypair[0], m)
    const decryptedM = vrf.decrypt(keypair[1], cipher)
    expect(decryptedM.equals(m)).toBeTruthy()
  })
})

describe('util convert methods test ModPGroup', () => {
  it('keys should be equals', () => {
    let vrf = new VerificatumModPCrypto(ZEUS_GROUP)
    let keypair = vrf.generateKeypair()
    let pkHex = convert.pkToHexModP(keypair[0])
    let skHex = convert.skToHex(keypair[1])
    let pk = convert.pkFromHexModP(pkHex, vrf.group)
    let sk = convert.skFromHex(skHex, vrf.group)
    expect(pk.equals(keypair[0])).toBeTruthy()
    expect(sk).toEqual(keypair[1])
  })
})

describe('util cipher serializer -- deserialize test ModPGroup', () => {
  it('ciphers must be equals', () => {
    let vrf = new VerificatumModPCrypto(ZEUS_GROUP)
    let keypair = vrf.generateKeypair()
    let m = vrf.group.randomElement(vrf.device, vrf.statDist)
    let cipher = vrf.encrypt(keypair[0], m)
    let serializedCipher = convert.serializeCipher(cipher)
    let deserializedCipher = convert.deserializeCipher(
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
