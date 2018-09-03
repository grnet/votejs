import { Sha256, string_to_bytes, bytes_to_hex } from 'asmcrypto.js'

export function sha256(str: string[]) {
  let sha = new Sha256()
  for (let part of str) {
    sha.process(string_to_bytes(part))
  }
  sha.finish()
  return bytes_to_hex(sha.result as Uint8Array)
}
