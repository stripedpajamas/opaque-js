const sodium = require('sodium-native')
const oprf = require('./oprf')

/**
 * Server-side authentication flow
 *
 * Configuration:
 *   - Key exchange embedded in messages (boolean)
 *   - Perform simple signature-based auth after OPAQUE (boolean)
 *
 * 1. Receive username, OPRF-alpha from client
 * 2. Retrieve user parameters from storage
 * 3. Compute OPRF-beta
 * 4. Send user parameters EnvU, vU and OPRF-beta to client
 * 5. Optionally perform simple signature-based auth
 */

class AuthenticationServer {
  constructor (config = {}) {
    this.config = Object.assign({}, {
      // default config options go here
    }, config)
  }
  start ({ userData, challenge }) {
    const { envelope, userPublicKey, oprfPublicKey, oprfSecretKey } = userData
    const response = oprf.response({ secretKey: oprfSecretKey, challenge })
    this.userPublicKey = userPublicKey
    return { envelope, publicKey: oprfPublicKey, response }
  }
  verify ({ proof }) {
    if (!this.userPublicKey) return false
    // given data signed with the user's private key,
    // verify signature is valid
    const msg = Buffer.alloc(proof.length - sodium.crypto_sign_BYTES)
    return sodium.crypto_sign_open(msg, proof, this.userPublicKey)
  }
}

module.exports = AuthenticationServer
