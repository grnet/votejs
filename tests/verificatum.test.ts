import "jest";
import { LargeInteger } from "verificatum/arithm";
import { RandomDevice } from "verificatum/crypto";
import { ModPGroup } from "verificatum/arithm";
import { ZEUS_PARAMS } from "./common";

const source = new RandomDevice();

describe("verificatum arithm", () => {
    it("large integers", () => {
        let int1 = new LargeInteger("ff");
        expect(int1.value[0]).toEqual(255);
        expect(int1.toHexString()).toEqual("ff");
    })

    it("modp group", () => {
        let { modulus, order, generator } = ZEUS_PARAMS;
        let group = new ModPGroup(modulus, order, generator, 1);
        expect(group).toBeInstanceOf(ModPGroup);
        let rnd = group.randomElement(source, 50);
        expect(rnd.value.toHexString().length).toEqual(512);
        expect(rnd).toBeTruthy();
    })
})