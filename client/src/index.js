const RegistrationClient = require('./register')

class Client {
  constructor () {
    this.registration = null
  }
  /**
   * Register a user with the server
   * @param {object} params
   * Step 1 requires username, password
   * Step 2 requires the server's OPRF response, OPRF public key, and KX key
   */
  register ({ username, password, response, oprfPublicKey, serverPublicKey }) {
    if (!this.registration) {
      this.registration = new RegistrationClient()
      return this.registration.start({ username, password })
    }
    const result = this.registration.register({
      response,
      oprfPublicKey,
      serverPublicKey
    })
    this.registration = null
    return result
  }
}

module.exports = Client
