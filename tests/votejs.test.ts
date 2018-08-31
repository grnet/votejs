import "jest";
import {LargeInteger, ECqPGroup, ModPGroup} from "verificatum/arithm";
import { arithm, convert } from "votejs/util";
import { GammaEncoder } from "votejs/encoders/gamma";
import { ZEUS_PARAMS } from "./common";
import {VerificatumModPCrypto, ModParams, VerificatumECqPCrypto} from "votejs/systems/verif";
import {ECP} from 'verificatum/arithm/ec/index';

describe("utils tests", () => {
  it("votejs arithm utils", () => {
    let a = new LargeInteger("ff");
    let b = new LargeInteger("00");
    expect(arithm.gt(a, b)).toEqual(true);
    expect(arithm.gt(b, a)).toEqual(false);
    expect(arithm.lt(b, a)).toEqual(true);
    expect(arithm.lt(a, b)).toEqual(false);

    expect(arithm.lte(a, a)).toEqual(true);
    expect(arithm.gte(a, a)).toEqual(true);

    expect(arithm.toNumber(a)).toEqual(255);
    expect(arithm.toLargeInteger(255).toHexString()).toEqual("ff");
  })
})

describe("gamma encoding", () => {
  it("should encode choices to integers", () => {
    let encoding = new GammaEncoder();

    let encoded = encoding.encode([1, 2], 2);
    expect(arithm.toNumber(encoded)).toEqual(6);
    encoded = encoding.encode([150, 10, 125], 300);
    expect(arithm.toNumber(encoded)).toEqual(13458406);

    let large = [];
    for (let i = 0; i < 100; i+=1) {
      large[i] = i;
    }
    encoded = encoding.encode(large, 300);
    expect(encoded.toHexString()).toEqual("131cf3263a45182a2186f53a6beae088cc27ac4919969aaedf466760b2c30850705dff5d87f5e9324901382a6b3fd5a61fecfe506f5bbd117ad2c62ec5f555c24c2839038291ebfc1316817973c7ebe47ef1e252dd4d8dcd5ee8d6deec17671ad4db08");

    encoded = encoding.encode([], 0);
    expect(arithm.toNumber(encoded)).toEqual(0);

    // test cached
    encoded = encoding.encode([1, 2], 2);
    expect(arithm.toNumber(encoded)).toEqual(6);
    encoded = encoding.encode([150, 10, 125], 300);
    expect(arithm.toNumber(encoded)).toEqual(13458406);
  })
})

describe("elgamal", () => {
  it("values should be integers", () => {
    let { modulus, order, generator } = ZEUS_PARAMS;
    let params = new ModParams(modulus, order, generator);
    let vrf = new VerificatumModPCrypto(params);
    let keypair = vrf.generateKeypair();
    expect(keypair[0].values[0].value).toBeInstanceOf(LargeInteger);
    expect(keypair[1].value).toBeInstanceOf(LargeInteger);
  })
})

describe("elgamal elliptic curves", () => {
    it("values should be ECP", () => {
        let ecGroup = new ECqPGroup("P-224");
        let vrf = new VerificatumECqPCrypto(ecGroup);
        let keypair = vrf.generateKeypair();
        expect(keypair[0].values[0].value).toBeInstanceOf(ECP);
        expect(keypair[1].value).toBeInstanceOf(LargeInteger);
    })
})

describe("votejs encryption decryption test ModPGroup", () => {
    it("message should be equal to decrypted message", () => {
        let { modulus, order, generator } = ZEUS_PARAMS;
        let params = new ModParams(modulus, order, generator);
        let vrf = new VerificatumModPCrypto(params);
        let keypair = vrf.generateKeypair();
        const m = vrf.group.randomElement(vrf.device, vrf.statDist);
        const cipher = vrf.encrypt(keypair[0], m);
        const decryptedM = vrf.decrypt(keypair[1], cipher);
        expect(decryptedM.equals(m)).toBeTruthy();
    })
})

describe("votejs encryption decryption test ECqPGroup", () => {
    it("message should be equal to decrypted message", () => {
        let ecGroup = new ECqPGroup("P-224");
        let vrf = new VerificatumECqPCrypto(ecGroup);
        let keypair = vrf.generateKeypair();
        const m = vrf.group.randomElement(vrf.device, vrf.statDist);
        const cipher = vrf.encrypt(keypair[0], m);
        const decryptedM = vrf.decrypt(keypair[1], cipher);
        expect(decryptedM.equals(m)).toBeTruthy();
    })
})

describe("util convert methods test ModPGroup", () => {
    it("keys should be equals", () => {
        let { modulus, order, generator } = ZEUS_PARAMS;
        let params = new ModParams(modulus, order, generator);
        let vrf = new VerificatumModPCrypto(params);
        let keypair = vrf.generateKeypair();
        let pkHex = convert.pkToHexModP(keypair[0]);
        let skHex = convert.skToHex(keypair[1]);
        let pk = convert.pkFromHexModP(pkHex, vrf.group);
        let sk = convert.skFromHex(skHex, vrf.group);
        expect(pk).toEqual(keypair[0]);
        expect(sk).toEqual(keypair[1]);
    })
})

describe("util convert methods test ECqPGroup", () => {
    it("keys should be equals", () => {
        let ecGroup = new ECqPGroup("P-224");
        let vrf = new VerificatumECqPCrypto(ecGroup);
        let keypair = vrf.generateKeypair();
        let pkHex = convert.pkToHexECqP(keypair[0]);
        let skHex = convert.skToHex(keypair[1]);
        let pk = convert.pkFromHexECqP(pkHex, vrf.group);
        let sk = convert.skFromHex(skHex, vrf.group);
        expect(pk).toEqual(keypair[0]);
        expect(sk).toEqual(keypair[1]);
    })
})

describe("util cipher serializer -- deserialize test ModPGroup", () => {
    it("ciphers must be equals", () => {
        let { modulus, order, generator } = ZEUS_PARAMS;
        let params = new ModParams(modulus, order, generator);
        let vrf = new VerificatumModPCrypto(params);
        let keypair = vrf.generateKeypair();
        let m = vrf.group.randomElement(vrf.device, vrf.statDist);
        let cipher = vrf.encrypt(keypair[0], m);
        let serializedCipher = convert.serializeModPCipher(cipher);
        let deserializedCipher =
            convert.deserializeModPCipher(vrf.group, serializedCipher);
        expect(cipher.equals(deserializedCipher)).toBeTruthy();
    })
})

describe("util cipher serializer -- deserialize test ECqPGroup", () => {
    it("ciphers must be equals", () => {
        let ecGroup = new ECqPGroup("P-224");
        let vrf = new VerificatumECqPCrypto(ecGroup);
        let keypair = vrf.generateKeypair();
        let m = vrf.group.randomElement(vrf.device, vrf.statDist);
        let cipher = vrf.encrypt(keypair[0], m);
        let curve = keypair[0].values[0].pGroup.curve;
        let serializedCipher = convert.serializeECqPCipher(curve, cipher);
        let deserializedCipher =
            convert.deserializeECqPCipher(vrf.group, serializedCipher);
        expect(cipher.equals(deserializedCipher)).toBeTruthy();
    })
})
