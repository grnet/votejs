import { ModPGroup, LargeInteger } from 'verificatum/arithm'
import { SHA256PRG, RandomDevice } from 'verificatum/crypto'
import { getGroupParams, arithm, random } from 'votejs/util'
import { sha256 } from 'votejs/hash'

// https://github.com/grnet/zeus/blob/master/zeus/core.py#L2268
export function numbersHash(numbers: LargeInteger[]): string {
  let strNumbers = Array.from(numbers, x => x.toHexString() + ':')
  return sha256(strNumbers)
}

// https://github.com/grnet/zeus/blob/master/zeus/core.py#L2177
export function strbinToInt(str: string): LargeInteger {
  let s = LargeInteger.ZERO
  let base = LargeInteger.ONE
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i)
    let cLI = arithm.toLargeInteger(c)
    s = cLI.mul(base).add(s)
    base = base.mul(arithm.toLargeInteger(256))
  }
  return s
}

// https://github.com/grnet/zeus/blob/master/zeus/core.py#L2299
function elementFromElementsHash(
  modulus: LargeInteger,
  generator: LargeInteger,
  order: LargeInteger,
  elements: LargeInteger[]
): LargeInteger {
  elements.unshift(modulus, generator, order)
  let digest = numbersHash(elements)
  let num = strbinToInt(digest)
  return generator.modPow(num, modulus)
}

abstract class Proof {
  constructor(public challenge: LargeInteger, public response: LargeInteger) {}
  abstract toArray(): LargeInteger[]
}

export class DLogProof extends Proof {
  constructor(
    public commitment: LargeInteger,
    public challenge: LargeInteger,
    public response: LargeInteger
  ) {
    super(challenge, response)
  }

  toArray(): LargeInteger[] {
    return [this.commitment, this.challenge, this.response]
  }
}

export class DDHTupleProof extends Proof {
  constructor(
    public baseCommitment: LargeInteger,
    public messageCommitment: LargeInteger,
    public challenge: LargeInteger,
    public response: LargeInteger
  ) {
    super(challenge, response)
  }

  toArray(): LargeInteger[] {
    return [
      this.baseCommitment,
      this.messageCommitment,
      this.challenge,
      this.response
    ]
  }
}

// as implemented at https://github.com/grnet/zeus/blob/master/zeus/core.py#L2305
export function proveDLog(
  group: ModPGroup,
  power: LargeInteger,
  dlog: LargeInteger,
  extra?: LargeInteger[],
  randomness?: LargeInteger // used only for test purpuses. Do not use it in production!!!!
) {
  let { order, generator, modulus } = getGroupParams(group)
  if (!randomness) {
    randomness = random.getRandomInt(LargeInteger.TWO, order)
  }
  let commitment = generator.modPow(randomness, modulus)
  if (!extra) {
    extra = []
  }
  extra.unshift(power, commitment)
  let challenge = elementFromElementsHash(modulus, generator, order, extra)
  // (randomness + challenge * dlog) % order
  let response = challenge
    .mul(dlog)
    .add(randomness)
    .mod(order)
  return new DLogProof(commitment, challenge, response)
}

// as implemented at https://github.com/grnet/zeus/blob/master/zeus/core.py#L2349
export function proveDDHTuple(
  group: ModPGroup,
  message: LargeInteger,
  basePower: LargeInteger,
  messagePower: LargeInteger,
  exponent: LargeInteger
) {
  let { order, generator, modulus } = getGroupParams(group)
  let randomness = random.getRandomInt(LargeInteger.TWO, order)
  let baseCommitment = generator.modPow(randomness, modulus)
  let messageCommitment = message.modPow(randomness, modulus)

  let args = [
    basePower,
    baseCommitment,
    message,
    messagePower,
    messageCommitment
  ]
  let challenge = elementFromElementsHash(modulus, generator, order, args)
  // (randomness + challenge * exponent) % order
  let response = challenge
    .mul(exponent)
    .add(randomness)
    .mod(order)

  return new DDHTupleProof(
    baseCommitment,
    messageCommitment,
    challenge,
    response
  )
}
