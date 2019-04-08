const RegistrationClient = require('./register')
const AuthenticationClient = require('./authenticate')

class Client {
  constructor () {
    this.registration = null
    this.authentication = null
  }
  /**
   * Register a user with the server
   * @param {object} params
   * Step 1 requires username, password
   * Step 2 requires the server's OPRF response, OPRF public key, and KX key
   * as well as the hardening params for the OPRF output
   */
  register ({
    username, password,
    response, oprfPublicKey, serverPublicKey, hashOpsLimit, hashMemLimit, hashSalt }) {
    if (!this.registration) {
      this.registration = new RegistrationClient()
      return this.registration.start({ username, password })
    }
    const result = this.registration.register({
      response,
      oprfPublicKey,
      serverPublicKey,
      hashOpsLimit,
      hashMemLimit,
      hashSalt
    })
    this.registration = null
    return result
  }
  /**
   * Authenticate with the server
   * @param {object} params
   * Step 1 requires username, password
   * Step 2 requires envelope, oprfPublicKey, response
   * as well as the hardening params for the OPRF output
   */
  authenticate ({
    username, password,
    envelope, oprfPublicKey, response, hashOpsLimit, hashMemLimit, hashSalt }) {
    if (!this.authentication) {
      this.authentication = new AuthenticationClient()
      return this.authentication.start({ username, password })
    }
    const { userSession } = this.authentication.authenticate({
      envelope,
      oprfPublicKey,
      response,
      hashOpsLimit,
      hashMemLimit,
      hashSalt
    })
    this.authentication = null
    return { userSession }
  }
}

module.exports = Client
