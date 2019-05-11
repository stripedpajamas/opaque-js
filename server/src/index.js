const sodium = require('sodium-native')
const RegistrationServer = require('./register')
const AuthenticationServer = require('./authenticate')

/**
 * Server class for registration and authentication
 *
 * The ops limit, memory limit, and salt for an iterative hash function
 * are set in the initial config and later communicated to the client
 * for hardening the OPRF output. sodium.crypto_pwhash_ALG_DEFAULT is
 * the algorithm used.
 *
 * The design paper states that for OPAQUE the salt can be set to a constant
 * such as all zeros. That is the default here.
 */

class Server {
  constructor (config = {}) {
    this.config = Object.assign({}, {
      pk: null,
      sk: null,
      hashOpsLimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      hashMemLimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      log: () => {}
    }, config)

    this.log = this.config.log

    // keep track of regs/auths because it's a multi-step flow
    this.registrations = new Map()
    this.authentications = new Map()

    this.init()
  }
  init () {
    const {
      crypto_kx_PUBLICKEYBYTES: pkLength,
      crypto_kx_SECRETKEYBYTES: skLength
    } = sodium
    const { pk, sk } = this.config
    if (!pk || !sk || pk.length !== pkLength || sk.length !== skLength) {
      this.log('Missing or invalid keypair, generating fresh')
      const newPk = Buffer.alloc(pkLength)
      const newSk = sodium.sodium_malloc(skLength)
      sodium.crypto_kx_keypair(newPk, newSk)
      this.config.pk = newPk
      this.config.sk = newSk

      // it is important to persist Server.config.pk
      // and Server.config.sk and pass them in at construction
      // for future registrations/authentications
    }

    const { hashSalt } = this.config
    if (!hashSalt || hashSalt.length !== sodium.crypto_pwhash_SALTBYTES) {
      this.log('No custom hash salt passed in, using default all-zeros')
      const newHashSalt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES) // all zeros
      this.config.hashSalt = newHashSalt
    }
  }
  /**
   * Begin registration a new user
   * @param {object} userParams
   * Step 1 requires username and challenge
   */
  beginRegistration (input = {}) {
    const { config = {}, username, challenge } = input
    if (!username || !challenge) {
      throw new Error('username and challenge required to begin registration')
    }
    // first step of registration flow
    const registration = new RegistrationServer(Object.assign({}, this.config, config))
    this.registrations.set(username, registration)
    const response = registration.start({ username, challenge })
    return response
  }
  /**
   * Complete registration of a new user
   * @param {object}
   * Step 2 requires username, envelope and publicKey
   */
  finishRegistration (input = {}) {
    const { username, envelope, publicKey } = input
    if (!username || !envelope || !publicKey) {
      throw new Error('username, envelope, and publicKey required to finish registration')
    }
    // second step of registration flow
    const registration = this.registrations.get(username)
    if (!registration) {
      throw new Error('no initialized registration found for user; must begin registration first')
    }
    const userData = registration.register({ envelope, publicKey })

    // cleanup registrations map
    this.registrations.delete(username)
    return userData
  }
  /**
   * Begins authentication of an already registered user
   * @param {object} params
   * Step 1 requires userData, challenge
   */
  beginAuthentication (input = {}) {
    const { config = {}, userData, challenge } = input
    if (!userData || !challenge) {
      throw new Error('userData and challenge required to begin authentication')
    }
    const { username } = userData
    // first step of authentication flow
    const authentication = new AuthenticationServer(Object.assign({}, this.config, config))
    this.authentications.set(username, authentication)
    const response = authentication.start({ userData, challenge })
    return response
  }
  /**
   * Completes authentication of an existing user
   * @param {object} params
   * Step 2 requires userData, userSession
   */
  finishAuthentication (input = {}) {
    const { userData, userSession } = input
    if (!userData || !userSession) {
      throw new Error('userData and userSession required to finish authentication')
    }
    const { username } = userData
    const authentication = this.authentications.get(username)
    if (!authentication) {
      throw new Error('no initialized authentication found for user; must begin authentication first')
    }
    const verified = authentication.authenticate({ userSession })

    // cleanup authentications map
    this.authentications.delete(username)
    return verified
  }
}

module.exports = Server
