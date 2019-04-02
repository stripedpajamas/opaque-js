const assert = require('assert')
const sodium = require('sodium-native')

/**
 * Server-side OPRF logic
 *
 * Using EC instead of legacy DH math
 *
 * 1. Receive challenge from client (alpha)
 * 2. Compute keypair (kU, vU) = (sk, pk)
 * 3. Compute response beta = (alpha * kU)
 * 4. Send vU, beta to client
 *
 * See https://download.libsodium.org/doc/advanced/point-arithmetic
 *
 */

exports.keypair = function keypair () {
  const sk = sodium.sodium_malloc(sodium.crypto_core_ed25519_SCALARBYTES) // kU
  const pk = Buffer.alloc(sodium.crypto_core_ed25519_BYTES) // vU
  sodium.randombytes_buf(sk)
  sodium.crypto_scalarmult_ed25519_base(pk, sk)

  return { publicKey: pk, secretKey: sk } // vU, kU
}

exports.response = function response ({ secretKey, challenge }) {
  assert.deepStrictEqual(
    challenge.length,
    sodium.crypto_scalarmult_ed25519_BYTES,
    'user oprf challenge is invalid length'
  )
  // compute b = a^k
  const beta = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_scalarmult_ed25519(beta, secretKey, challenge)
  return beta
}
