import { LargeInteger } from 'verificatum/arithm'

export const arithm = {
  gt(num1: LargeInteger, num2: LargeInteger) {
    return num1.cmp(num2) > 0
  },
  gte(num1: LargeInteger, num2: LargeInteger) {
    return num1.cmp(num2) >= 0
  },
  lt(num1: LargeInteger, num2: LargeInteger) {
    return num1.cmp(num2) < 0
  },
  lte(num1: LargeInteger, num2: LargeInteger) {
    return num1.cmp(num2) <= 0
  },
  toLargeInteger(num: number): LargeInteger {
    return new LargeInteger(num.toString(16))
  },
  toNumber(num: LargeInteger): number {
    return parseInt(num.toHexString(), 16)
  }
}
