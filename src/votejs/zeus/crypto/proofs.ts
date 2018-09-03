import { ModPGroup, LargeInteger } from 'verificatum/arithm'
import { getGroupParams } from 'votejs/util'

export class Proof {
  constructor(
    public commitment: LargeInteger,
    public challenge: LargeInteger,
    public response: LargeInteger
  ) {}
  toArray() {
    return [this.commitment, this.challenge, this.response]
  }
}

// as implemented at https://github.com/grnet/zeus/blob/master/zeus/core.py#L2305
export function proveDLog(
  group: ModPGroup,
  power: LargeInteger,
  dlog: LargeInteger,
  extra?: LargeInteger[]
) {
  let { order, generator, modulus } = getGroupParams(group)
  return new Proof(comm, challenge, response)
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
  return new Proof(comm, challenge, response)
}
