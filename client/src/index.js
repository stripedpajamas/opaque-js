const RegistrationClient = require('./register')
const AuthenticationClient = require('./authenticate')

class Client {
  constructor () {
    this.registration = null
    this.authentication = null
  }
  /**
   * Begin registration of a user with the server
   * @param {object} params
   * Step 1 requires username, password
   */
  beginRegistration ({ username, password }) {
    this.registration = new RegistrationClient()
    return this.registration.start({ username, password })
  }
  /**
   * Finish registration of a new user with a server
   * @param {object} params
   * Step 2 requires the server's OPRF response, OPRF public key, and KX key
   * as well as the hardening params for the OPRF output
   */
  finishRegistration ({ response, oprfPublicKey, serverPublicKey, hashOpsLimit, hashMemLimit, hashSalt }) {
    if (!this.registration) {
      throw new Error('must begin registration before finishing')
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
   * Begin authentication with the server
   * @param {object} params
   * Step 1 requires username, password
   */
  beginAuthentication ({ username, password }) {
    this.authentication = new AuthenticationClient()
    return this.authentication.start({ username, password })
  }
  /**
   * Finish authentication with the server
   * @param {object} params
   * Step 2 requires envelope, oprfPublicKey, response
   * as well as the hardening params for the OPRF output
   */
  finishAuthentication ({ envelope, oprfPublicKey, response, hashOpsLimit, hashMemLimit, hashSalt }) {
    if (!this.authentication) {
      throw new Error('must begin authentication before finishing')
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
