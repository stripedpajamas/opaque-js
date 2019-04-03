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
 * 4. Send user parameters EnvU, vU, KX public key and OPRF-beta to client
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
    return { envelope, oprfPublicKey, kxPublicKey: this.config.pk, response }
  }
  authenticate ({ userSession }) {
    if (!this.userPublicKey) return false
    const serverSession = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
    sodium.crypto_kx_server_session_keys(
      serverSession,
      null,
      this.config.pk,
      this.config.sk,
      this.userPublicKey
    )
    return sodium.sodium_memcmp(userSession, serverSession)
  }
}

module.exports = AuthenticationServer
