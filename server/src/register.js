const oprf = require('./oprf')

/**
 * Server-side registration flow
 *
 * 1. Receive id/username, OPRF challenge from client
 * 2. Generate random per-user OPRF key
 * 3. Send OPRF public key, KE public key, OPRF response to client
 * 4. Receive envelope, user public key from client
 * 5. Save user parameters to storage, keyed by id/username
 */

class RegistrationServer {
  constructor (config = {}) {
    this.config = Object.assign({}, {
      // default config options go here
    }, config)
  }
  start ({ username, challenge }) {
    const { publicKey, secretKey } = oprf.keypair()
    const response = oprf.response({ secretKey, challenge })

    // these will be persisted at the end of the flow
    this.username = username
    this.oprfPublicKey = publicKey
    this.oprfSecretKey = secretKey

    return {
      serverPublicKey: this.config.pk,
      oprfPublicKey: this.oprfPublicKey,
      response
    }
  }
  register ({ envelope, publicKey }) {
    // user provides envelope and their public key
    // we persist a user record { env, pubU, kU, vU }
    // where kU, vU are secretKey, publicKey from OPRF
    return {
      username: this.username,
      envelope,
      userPublicKey: publicKey,
      oprfPublicKey: this.oprfPublicKey,
      oprfSecretKey: this.oprfSecretKey
    }
  }
}

module.exports = RegistrationServer
