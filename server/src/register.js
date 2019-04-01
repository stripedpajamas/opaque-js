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

 class Server {
  constructor (config = {}) {
    this.config = Object.assign({}, {
      // default config options go here
    }, config)
  }
  handler (input) {

  }
 }

 module.exports = Server
