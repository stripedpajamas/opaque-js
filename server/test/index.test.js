const test = require('ava')
const sodium = require('sodium-native')
const Server = require('../src')

test('init creates a keypair if none passed in', (t) => {
  const server = new Server()
  t.is(server.config.pk.length, sodium.crypto_kx_PUBLICKEYBYTES, 'pk correct length')
  t.is(server.config.sk.length, sodium.crypto_kx_SECRETKEYBYTES, 'sk correct length')
})
