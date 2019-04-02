const test = require('ava')
const sodium = require('sodium-native')
const Server = require('../src')

test('init creates a keypair if none passed in', (t) => {
  const server = new Server()
  const keypair = server.init()
  t.is(server.config.pk.length, sodium.crypto_kx_PUBLICKEYBYTES, 'pk correct length')
  t.is(server.config.sk.length, sodium.crypto_kx_SECRETKEYBYTES, 'sk correct length')
  t.is(keypair.pk.length, sodium.crypto_kx_PUBLICKEYBYTES, 'pk correct length')
  t.is(keypair.sk.length, sodium.crypto_kx_SECRETKEYBYTES, 'sk correct length')
})

test('registration flow', (t) => {
  const server = new Server()

  const username = 'pete'
  const secret = Buffer.alloc(sodium.crypto_core_ed25519_UNIFORMBYTES)
  const challenge = Buffer.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  sodium.randombytes_buf(secret)
  sodium.crypto_core_ed25519_from_uniform(challenge, secret)
  const { publicKey, response } = server.register({ username, challenge })

  t.is(server.registrations.size, 1)
  t.is(publicKey.length, sodium.crypto_core_ed25519_BYTES)
  t.is(response.length, sodium.crypto_core_ed25519_BYTES)
})
