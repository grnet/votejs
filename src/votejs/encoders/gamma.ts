import { ChoiceEncoder, Choice } from 'votejs/types'
import { LargeInteger } from 'verificatum/arithm'
import { arithm } from 'votejs/util'

const _offsets: { [s: string]: Array<LargeInteger> } = {}
const _terms: { [s: string]: { [s: string]: LargeInteger } } = {}
const _factors: { [s: string]: { [s: string]: LargeInteger } } = {}

function get_factor(b: LargeInteger, n: LargeInteger): LargeInteger {
  let hexB = b.toHexString()
  let hexN = n.toHexString()
  let hexONE = LargeInteger.ONE.toHexString()
  let t: { [s: string]: LargeInteger } = {}

  if (arithm.lte(n, LargeInteger.ONE)) {
    return LargeInteger.ONE
  }

  if (hexB in _factors) {
    t = _factors[hexB]
    if (hexN in t) {
      return t[hexN]
    }
  } else {
    t = {}
    t[hexONE] = LargeInteger.ONE
    _factors[hexB] = t
  }

  let i = n
  let hexI = i.toHexString()
  while (1) {
    i = i.sub(LargeInteger.ONE)
    hexI = i.toHexString()
    if (hexI in t) {
      break
    }
  }

  let f = t[hexI]
  while (1) {
    f = f.mul(b.add(i))
    i = i.add(LargeInteger.ONE)
    hexI = i.toHexString()
    t[hexI] = f
    if (arithm.lte(i, n)) {
      break
    }
  }
  return f
}

function get_term(n: LargeInteger, k: LargeInteger): LargeInteger {
  let hexN = n.toHexString()
  let hexK = k.toHexString()
  let t: { [s: string]: LargeInteger } = {}

  if (arithm.gte(k, n)) {
    return LargeInteger.ONE
  }

  if (hexN in _terms) {
    t = _terms[hexN]
    if (hexK in t) {
      return t[hexK]
    }
  } else {
    t = {}
    t[hexN] = LargeInteger.ONE
    _terms[hexN] = t
  }

  let m = k
  let hexM = m.toHexString()
  while (1) {
    m = m.add(LargeInteger.ONE)
    hexM = m.toHexString()
    if (hexM in t) {
      break
    }
  }

  let term = t[hexM]
  while (1) {
    term = term.mul(m)
    m = m.sub(LargeInteger.ONE)
    hexM = m.toHexString()
    t[hexM] = term
    if (arithm.lte(m, k)) {
      break
    }
  }
  return term
}

function get_offsets(n: LargeInteger): Array<LargeInteger> {
  let hex = n.toHexString()
  if (hex in _offsets) {
    return _offsets[hex]
  }

  let offsets: Array<LargeInteger> = []
  let sumus = LargeInteger.ZERO
  let i = LargeInteger.ZERO
  while (1) {
    let term = get_term(n, n.sub(i))
    sumus = sumus.add(term)
    offsets.push(sumus)
    if (i.equals(n)) {
      break
    }
    i = i.add(LargeInteger.ONE)
  }
  _offsets[hex] = offsets
  return offsets
}

/**
 * Return the index where to insert item x in list a, assuming a is sorted.
 * https://github.com/python/cpython/blob/2.7/Lib/bisect.py#L24
 *  
 * @param a 
 * @param x 
 * @param lo
 * @param hi
 */
function bisect_right(
  a: Array<LargeInteger>, 
  x: LargeInteger, 
  lo=LargeInteger.ONE, 
  hi=arithm.toLargeInteger(a.length)
): LargeInteger {
  while (arithm.lt(lo, hi)) {
    let mid = (lo.add(hi))
    mid = mid.div(LargeInteger.TWO);
    // TODO: assert arithm.toNumber(mid) < largest js number
    if (arithm.lt(x, a[arithm.toNumber(mid)])) {
      hi = mid
    } else {
      lo = mid.add(LargeInteger.ONE)
    }
  }
  return lo
}

/**
 * Zeus gamma_encode method.
 * https://github.com/grnet/zeus/blob/master/zeus/core.py#L1498
 * 
 * @param choices
 * @param nrOptions
 * @returns LargeInteger
 */
export class GammaEncoder implements ChoiceEncoder {
  encode(choices: Choice, nrOptions: number): LargeInteger {
    if (!nrOptions) {
      return LargeInteger.ZERO
    }
    let nrOptionsBig = arithm.toLargeInteger(nrOptions)
    let nrChoices = arithm.toLargeInteger(choices.length)

    let offsets = get_offsets(nrOptionsBig)
    // TODO: assert nrOptions < largest js number
    let sumus = offsets[arithm.toNumber(nrChoices.sub(LargeInteger.ONE))]
    let b = nrOptionsBig.sub(nrChoices)
    let i = 1
    while (1) {
      let choice = arithm.toLargeInteger(choices.concat().reverse()[i - 1])
      let factor = get_factor(b, arithm.toLargeInteger(i))
      sumus = sumus.add(choice.mul(factor))
      if (i >= choices.length) {
        break
      }
      i += 1
    }
    return sumus
  }

  /**
   * Zeus gamma_decode.
   * https://github.com/grnet/zeus/blob/master/zeus/core.py#L1498
   * 
   * @param sumus 
   * @returns Choice
   */
  decode(sumus: LargeInteger, nrOptions: number): Choice {
    if (sumus.iszero()) {
      return [];
    }
 
    let nrOptionsLI = arithm.toLargeInteger(nrOptions)

    let offsets = get_offsets(nrOptionsLI)
    let nr_choices = bisect_right(offsets, sumus)
    let index = arithm.toNumber(nr_choices.sub(LargeInteger.ONE))
    sumus = sumus.sub(offsets[index])

    let choices:Choice = [];

    let b = nrOptionsLI.sub(nr_choices)
    let i = nr_choices
    
    while (1) {
      // divmod
      let factorBI = get_factor(b, i)
      let choice = sumus.div(factorBI)
      sumus = sumus.mod(factorBI)
      let choiceN = arithm.toNumber(choice)
      choices.push(choiceN)
      if (arithm.lte(i, LargeInteger.ONE)) {
        break 
      }
      i = i.sub(LargeInteger.ONE) 
    }
    return choices
  }
}
