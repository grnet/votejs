const data = require('./zeus_regression_data')
import { LargeInteger, ModPGroup } from 'verificatum/arithm'
import { SHA256PRG, RandomDevice } from 'verificatum/crypto'

const modulus =
  '9decdda7acdef3b3b7f2742887635785a12a3ce10183ffe882573830b28b7939e3feec0c2a850b88e96754ee46edf4b858b19c9587a7a29e72d6c4583478d4ee377a6111eb2a651d8ef9994c2fbb7a2343ec3fa7ef16317ebacd64d8cbd7ebdf3f68e7f63e606854aa609538a25818b8b661032e3ce8c5a1657d82e90d2249d3af079e7de9bf37e0911d6a9d396e2dda3a7793f0ba5ce0beb1f70fc1b5c8726805471028e176fb6ec4f9ce590e4a4506584248157ec44c36fd35d73871efbd8cf59d22dbeda34acb008dc303b1252c428fc6b8231f1bfdba3119e9743ea6f43ace51e347e13d18b1f5fd54c2846781a85290450ef9e37503d30d03315d569c73'
const order =
  '4ef66ed3d66f79d9dbf93a1443b1abc2d0951e7080c1fff4412b9c185945bc9cf1ff7606154285c474b3aa772376fa5c2c58ce4ac3d3d14f396b622c1a3c6a771bbd3088f595328ec77ccca617ddbd11a1f61fd3f78b18bf5d66b26c65ebf5ef9fb473fb1f30342a55304a9c512c0c5c5b3081971e7462d0b2bec174869124e9d783cf3ef4df9bf0488eb54e9cb716ed1d3bc9f85d2e705f58fb87e0dae4393402a3881470bb7db7627ce72c872522832c21240abf62261b7e9aeb9c38f7dec67ace916df6d1a5658046e181d892962147e35c118f8dfedd188cf4ba1f537a1d6728f1a3f09e8c58fafeaa614233c0d4294822877cf1ba81e9868198aeab4e39'
const generator =
  '97d518e0f381ba1a990d70e4349d2affa2663fa85bde092507b827113607767053fe01f3432f1aa976824f1e8990ceb2349c5cb124535c0a0b32f65ab9009e95f4012820178483644b282134666ca71e62eaadeb8b80cccd0a690feca69c292036d6c2ab642e4a6ddc529ca687e16c48492e470ee82de4622235e5dd511eb86162fc700e53da42f27ddf640d4f15de7bf34bbd4107531f8448c2e1dca378e553801152ba96b5bb0fb716575a8c0a88b13ea74b53816a13fad7d1c1c6a822793922fe0eefc78463bea9465d745ba5ee35f1e72b95a076c20f6bbf26e93f8a8974db253f8d6519cb61474ffba95f2c749f1ccf93562983306437ac492dc22f8d77'

let device = new RandomDevice() // random source
let seed = device.getBytes(SHA256PRG.seedLength)
export const randomSource = new SHA256PRG() // ran

export const ZEUS_PARAMS = {
  modulus: new LargeInteger(modulus),
  order: new LargeInteger(order),
  generator: new LargeInteger(generator)
}

export const ZEUS_GROUP = new ModPGroup(
  ZEUS_PARAMS.modulus,
  ZEUS_PARAMS.order,
  ZEUS_PARAMS.generator,
  1
)

function serializeHex(data: any) {
  for (let key in data) {
    let val = data[key]
    if (typeof val === 'object') {
      val = serializeHex(val)
    }
    if (typeof val === 'string') {
      if (val.startsWith('0x')) {
        val = new LargeInteger(val.slice(2))
      }
    }
    data[key] = val
  }
  return data
}

export const regressionData = serializeHex(data)
