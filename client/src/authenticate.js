const sodium = require('sodium-native')
const oprf = require('./oprf')

/**
 * Client-side authentication flow
 *
 * 1. Send username, OPRF-alpha to server
 * 2. Receive encrypted user parameters and OPRF-beta from server
 * 3. Compute decryption key from OPRF output
 * 4. Decrypt user parameters
 */

class AuthenticationClient {
  start ({ username, password }) {
    // but buffered password on class
    this.password = Buffer.from(password)

    const { challenge, r } = oprf.challenge({ password: this.password })

    // save random scalar and username for later
    this.randomScalar = r
    this.username = username

    return { username, challenge }
  }
  authenticate ({ envelope, oprfPublicKey, response }) {
    // compute rwd which is the key used to decrypt envelope
    const rwd = oprf.output({
      password: this.password,
      response,
      oprfPublicKey,
      r: this.randomScalar
    })
    const { ciphertext, nonce } = envelope
    const openedEnvelope = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES)
    const success = sodium.crypto_secretbox_open_easy(openedEnvelope, ciphertext, nonce, rwd)
    if (!success) return { userSession: Buffer.alloc(0) }

    // extract the data from the opened envelope
    let {
      userPublicKey,
      userSecretKey,
      serverPublicKey
    } = JSON.parse(openedEnvelope.toString())
    // JSON encodes buffers in a funny way
    userPublicKey = Buffer.from(userPublicKey.data)
    userSecretKey = Buffer.from(userSecretKey.data)
    serverPublicKey = Buffer.from(serverPublicKey.data)
    // generate the user session key from the info we now have
    const userSession = sodium.sodium_malloc(sodium.crypto_kx_SESSIONKEYBYTES)
    sodium.crypto_kx_client_session_keys(
      userSession,
      null,
      userPublicKey,
      userSecretKey,
      serverPublicKey
    )
    return { userSession }
  }
}

module.exports = AuthenticationClient
