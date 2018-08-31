import { SLI } from 'verificatum/arithm/sli';
import {LargeInteger} from 'verificatum/arithm';

export class ECP {
    x: SLI
    y: SLI
    z: SLI
    constructor(len: number, x: SLI, y: SLI, z: SLI)
}

export class EC {
    constructor(modulus: LargeInteger, a: LargeInteger, b: LargeInteger)
    affine(A: ECP): null
}