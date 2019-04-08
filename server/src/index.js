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
   * Register a new user
   * @param {object} userParams
   * Step 1 requires username and challenge
   * Step 2 requires username, envelope and publicKey
   */
  register ({ config = {}, username, challenge, envelope, publicKey }) {
    if (!this.registrations.has(username)) {
      // first step of registration flow
      const registration = new RegistrationServer(Object.assign({}, this.config, config))
      this.registrations.set(username, registration)
      const response = registration.start({ username, challenge })
      return response
    }
    // second step of registration flow
    const registration = this.registrations.get(username)
    const userData = registration.register({ envelope, publicKey })

    // cleanup registrations map
    this.registrations.delete(username)
    return userData
  }
  /**
   * Authenticate an already registered user
   * @param {object} params
   * Step 1 requires userData, challenge
   * Step 2 requires userData, userSession
   */
  authenticate ({ config = {}, userData, challenge, userSession }) {
    const { username } = userData
    if (!this.authentications.has(username)) {
      // first step of authentication flow
      const authentication = new AuthenticationServer(Object.assign({}, this.config, config))
      this.authentications.set(username, authentication)
      const response = authentication.start({ userData, challenge })
      return response
    }
    // second step of authentication flow
    const authentication = this.authentications.get(username)
    const verified = authentication.authenticate({ userSession })

    // cleanup authentications map
    this.authentications.delete(username)
    return verified
  }
}

module.exports = Server
