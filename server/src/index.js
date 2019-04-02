const { EventEmitter } = require('events')
const sodium = require('sodium-native')
const { EVENTS } = require('./constants')

/**
 * Server class for registration and authentication
 */

class Server extends EventEmitter {
  constructor (config = {}) {
    super()
    this.config = Object.assign({}, {
      pk: null,
      sk: null,
      log: () => {}
    }, config)

    this.log = this.config.log

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
      const newSk = Buffer.alloc(skLength)
      sodium.crypto_kx_keypair(newPk, newSk)
      this.config.pk = newPk
      this.config.sk = newSk

      // allow consumer to persist keypair
      this.emit(EVENTS.KEYPAIR_GENERATED, { pk: newPk, sk: newSk })
    }
  }
}

module.exports = Server
