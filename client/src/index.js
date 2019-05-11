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
  beginRegistration (input = {}) {
    const { username, password } = input
    if (!username || !password) {
      throw new Error('username and password required to register')
    }
    this.registration = new RegistrationClient()
    return this.registration.start({ username, password })
  }
  /**
   * Finish registration of a new user with a server
   * @param {object} params
   * Step 2 requires the server's OPRF response, OPRF public key, and KX key
   * as well as the hardening params for the OPRF output
   */
  finishRegistration (input = {}) {
    const {
      response,
      oprfPublicKey,
      serverPublicKey,
      hashOpsLimit,
      hashMemLimit,
      hashSalt
    } = input
    if (!response || !oprfPublicKey || !serverPublicKey || !hashOpsLimit || !hashMemLimit || !hashSalt) {
      throw new Error('missing parameters in finish registration step')
    }
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
  beginAuthentication (input = {}) {
    const { username, password } = input
    if (!username || !password) {
      throw new Error('username and password required to register')
    }
    this.authentication = new AuthenticationClient()
    return this.authentication.start({ username, password })
  }
  /**
   * Finish authentication with the server
   * @param {object} params
   * Step 2 requires envelope, oprfPublicKey, response
   * as well as the hardening params for the OPRF output
   */
  finishAuthentication (input = {}) {
    const {
      envelope,
      oprfPublicKey,
      response,
      hashOpsLimit,
      hashMemLimit,
      hashSalt
    } = input
    if (!envelope || !oprfPublicKey || !response || !hashOpsLimit || !hashMemLimit || !hashSalt) {
      throw new Error('missing parameters in finish registration step')
    }
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
