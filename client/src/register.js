const sodium = require('sodium-native')
const oprf = require('./oprf')

/**
 * Client-side registration flow
 *
 * 1. Send username to server
 * 2. Generate keypair
 * 3. Perform OPRF flow with password as input
 * 4. Encrypt keypair and server public key using OPRF output as key
 * 5. Send encrypted parameters and public key to server
 */

class RegistrationClient {
  start ({ username, password }) {
    // generate keypair
    const {
      crypto_kx_PUBLICKEYBYTES: pkLength,
      crypto_kx_SECRETKEYBYTES: skLength
    } = sodium
    const pk = Buffer.alloc(pkLength)
    const sk = sodium.sodium_malloc(skLength)
    sodium.crypto_kx_keypair(pk, sk)
    this.pk = pk
    this.sk = sk

    // but buffered password on class
    this.password = Buffer.from(password)

    // begin OPRF flow
    const { challenge, r } = oprf.challenge({ password: this.password })
    // we will need the random scalar later
    this.randomScalar = r

    // challenge can now be consumed be the server
    return { username, challenge }
  }
  register ({ response, oprfPublicKey, publicKey }) {
    // server sent back response to challenge and OPRF public key
    // complete the OPRF flow
    const rwd = oprf.output({
      password: this.password,
      response,
      oprfPublicKey,
      r: this.randomScalar
    })

    // use rwd as the key to an authenticated encryption of
    // client's keypair and server's kx public key
    const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
    const message = Buffer.from(JSON.stringify({
      userPublicKey: this.pk,
      userSecretKey: this.sk,
      serverPublicKey: publicKey
    }))
    const ciphertext = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)

    sodium.randombytes_buf(nonce) // insert random data into nonce
    sodium.crypto_secretbox_easy(ciphertext, message, nonce, rwd)

    const envelope = { ciphertext, nonce }
    return { publicKey: this.pk, envelope }
  }
}

module.exports = RegistrationClient
