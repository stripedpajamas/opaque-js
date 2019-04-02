const oprf = require('./oprf')

/**
 * Server-side registration flow
 *
 * 1. Receive ID from client
 * 2. Generate keypair if no keypair exists globally
 * 3. Persist keypair for future registrations/authentications
 * 4. Generate random per-user OPRF key
 * 5. Send public key to client
 * 6. Perform OPRF flow
 * 7. Receive user parameters from client
 * 8. Save user parameters to storage, keyed by username
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
    this.publicKey = publicKey
    this.secretKey = secretKey

    return { publicKey, response }
  }
  register ({ envelope, publicKey }) {
    // user provides envelope and their public key
    // we persist a user record { env, pubU, kU, vU }
    // where kU, vU are secretKey, publicKey from OPRF
    return {
      username: this.username,
      envelope,
      userPublicKey: publicKey,
      oprfPublicKey: this.publicKey,
      oprfSecretKey: this.secretKey
    }
  }
}

module.exports = RegistrationServer
