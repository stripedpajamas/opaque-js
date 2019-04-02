const { EventEmitter } = require('events')
const { generateOPRFKey } = require('./oprf')

/**
 * Server-side registration flow
 *
 * 1. Receive username from client
 * 2. Generate keypair if no keypair exists globally
 * 3. Persist keypair for future registrations/authentications
 * 4. Generate random per-user OPRF key
 * 5. Send public key to client
 * 6. Perform OPRF flow
 * 7. Receive user parameters from client
 * 8. Save user parameters to storage, keyed by username
 */

class RegistrationServer extends EventEmitter {
  constructor (config = {}) {
    super()
    this.config = Object.assign({}, {
      // default config options go here
    }, config)
  }
  init () {
    // if doing per-session keypairs
    // generate keypairs and emit keypair save event
    // generate and save per-user OPRF key kU
    this.OPRFKey = generateOPRFKey()
  }
  register () {

  }
}

module.exports = RegistrationServer
