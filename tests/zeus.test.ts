import "jest";
import {LargeInteger, ECqPGroup, ModPGroup, ModPGroupElement} from "verificatum/arithm";
import { ElGamal, ModPElGamal } from "verificatum/crypto";
import { regressionData as data, randomSource } from "./common";
import { convert, arithm } from "votejs/util";

describe("zeus regression tests", () => {
  it("expect zeus numbers to equal votejs results", () => {
      let group = new ModPGroup(data.system.modulus, data.system.order, data.system.generator, 1);
      let crypto:ModPElGamal = new ElGamal(true, group, randomSource, 1);
      let pub = convert.pkFromInt(data.public as LargeInteger, group);
      type DataProof = {
          commitment: LargeInteger
          challenge: LargeInteger
          response: LargeInteger
      };
      type DataVote = {
          alpha: LargeInteger
          beta: LargeInteger
          encoded: number
          randomness: LargeInteger
          proof: DataProof
      };
      let votes = data.votes as Array<DataVote>;
      for (let vote of votes) {
          let message = arithm.toLargeInteger(vote.encoded);
          message = message.add(LargeInteger.ONE);
          if (message.legendre(group.modulus) !== 1) {
            message = group.modulus.sub(message);
          }
          let messageElement = convert.toGroupElement(message, group);
          let random = convert.toFieldElement(vote.randomness, group);
          let result = crypto.encrypt(pub, messageElement, random);
          expect(result.values[0].value.toHexString()).toEqual(vote.alpha.toHexString());
          expect(result.values[1].value.toHexString()).toEqual(vote.beta.toHexString());
      }
  })
})