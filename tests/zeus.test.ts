import 'jest'
import {
  LargeInteger,
  ModPGroup,
} from 'verificatum/arithm'
import { ElGamal, ModPElGamal } from 'verificatum/crypto'
import { regressionData as data, randomSource } from './common'
import { convert, arithm } from 'votejs/util'
import { GammaEncoder } from 'votejs/crypto'
import { zeusData } from './zeus_test_data'
import {
  numbersHash,
  strbinToInt,
  proveDLog,
  proveDDHTuple
} from 'votejs/zeus/crypto/proofs'

describe('zeus regression tests', () => {
  it('expect zeus numbers to equal votejs results', () => {
    let group = new ModPGroup(
      data.system.modulus,
      data.system.order,
      data.system.generator,
      1
    )
    let crypto: ModPElGamal = new ElGamal(true, group, randomSource, 1)
    let pub = convert.pkFromInt(data.public as LargeInteger, group)
    type DataProof = {
      commitment: LargeInteger
      challenge: LargeInteger
      response: LargeInteger
    }
    type DataVote = {
      alpha: LargeInteger
      beta: LargeInteger
      encoded: number
      randomness: LargeInteger
      proof: DataProof
    }
    let votes = data.votes as Array<DataVote>
    for (let vote of votes) {
      let message = arithm.toLargeInteger(vote.encoded)
      message = message.add(LargeInteger.ONE)
      if (message.legendre(group.modulus) !== 1) {
        message = group.modulus.sub(message)
      }
      let messageElement = convert.toGroupElement(message, group)
      let random = convert.toFieldElement(vote.randomness, group)
      let result = crypto.encrypt(pub, messageElement, random)
      expect(result.values[0].value.toHexString()).toEqual(
        vote.alpha.toHexString()
      )
      expect(result.values[1].value.toHexString()).toEqual(
        vote.beta.toHexString()
      )
    }
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
      zeusData.GammaEncodingData.gammaEncodedArray
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

describe('numbersHash and strbinToInt Functions tests', () => {
  it('check hash and Integer', () => {
    let elements = zeusData.HashData.elements
    let numbersHashValue = numbersHash(elements)
    expect(numbersHashValue).toEqual(zeusData.HashData.elementsHash)

    let nullHash = numbersHash([])
    expect(nullHash).toEqual(zeusData.HashData.nullHash)

    let intFromHash = strbinToInt(zeusData.HashData.strBinString)
    expect(arithm.toNumber(intFromHash)).toEqual(zeusData.HashData.strBinNum)

    let intNull = strbinToInt('')
    expect(arithm.toNumber(intNull)).toEqual(0)

    let intZeroHash = strbinToInt('0')
    expect(arithm.toNumber(intZeroHash)).toEqual(48)
  })
})

describe('proveDLog test', () => {
  it('check if returns values are equals to zeus prove_dlog function', () => {
    let dt = zeusData.DLogProofData
    let group = new ModPGroup(dt.modulus, dt.order, dt.generator, 1)
    let proof = proveDLog(group, dt.power, dt.dlog, dt.extra, dt.randomness)
    expect(proof.commitment.equals(dt.commitment)).toBeTruthy()
    expect(proof.challenge.equals(dt.challenge)).toBeTruthy()
    expect(proof.response.equals(dt.response)).toBeTruthy()
  })
})

describe('proveDDHTuple test', () => {
  it('check if returns values are equals to zeus prove_dhh_tuple function', () => {
    let dt = zeusData.DHHTupleData
    let group = new ModPGroup(dt.modulus, dt.order, dt.generator, 1)
    let proof = proveDDHTuple(
      group,
      dt.message,
      dt.basePower,
      dt.messagePower,
      dt.exponent,
      dt.randomness
    )
    expect(proof.baseCommitment.equals(dt.baseCommitment)).toBeTruthy()
    expect(proof.messageCommitment.equals(dt.messageCommitment)).toBeTruthy()
    expect(proof.challenge.equals(dt.challenge)).toBeTruthy()
    expect(proof.response.equals(dt.response)).toBeTruthy()
  })
})
