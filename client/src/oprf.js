const sodium = require('sodium-native')

/**
 * Server-side OPRF logic
 *
 * Using EC instead of legacy DH math
 *
 * 1. Compute challenge (alpha)
 * 2. Receive response from server (beta)
 * 3. Compute OPRF output
 *
 * See https://download.libsodium.org/doc/advanced/point-arithmetic
 *
 */

exports.challenge = function challenge ({ password }) {
  // hash password first to turn it into 32 bytes
  const hashedPwd = Buffer.alloc(32)
  sodium.crypto_generichash(hashedPwd, password)
  // map password to point on curve
  const mappedPwd = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_from_uniform(mappedPwd, hashedPwd)
  // blind password to safely send to server (challenge = H'(pwd) * g^r)
  const r = Buffer.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
  const gr = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  const challenge = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_scalar_random(r)
  sodium.crypto_scalarmult_ed25519_base_noclamp(gr, r)
  sodium.crypto_core_ed25519_add(challenge, mappedPwd, gr)
  return { challenge, r }
}

exports.output = function output ({ password, response, oprfPublicKey, r }) {
  // compute response * publicKey^(-r)
  const ir = Buffer.alloc(sodium.crypto_core_ed25519_SCALARBYTES) // inverse of r
  const pir = Buffer.alloc(sodium.crypto_core_ed25519_BYTES) // publicKey ^ ir
  sodium.crypto_core_ed25519_scalar_negate(ir, r)
  sodium.crypto_scalarmult_ed25519_noclamp(pir, ir, oprfPublicKey)
  const result = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_add(result, response, pir)

  // hash password + publicKey + challenge/response result
  const out = sodium.sodium_malloc(32) // Rwd in the paper ("randomized password")
  sodium.crypto_generichash_batch(out, [
    password,
    oprfPublicKey,
    result
  ])
  return out
}
