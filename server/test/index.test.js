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

  const envelope = {}
  const userPublicKey = Buffer.alloc(0)
  const userData = server.register({ username, envelope, publicKey: userPublicKey })

  t.is(server.registrations.size, 0)
  t.is(userData.userPublicKey, userPublicKey)
  t.is(userData.envelope, envelope)
  t.is(userData.username, username)
  t.is(userData.oprfPublicKey.length, sodium.crypto_core_ed25519_BYTES)
  t.is(userData.oprfSecretKey.length, sodium.crypto_core_ed25519_SCALARBYTES)
})

test('authentication flow', (t) => {
  const server = new Server()

  const username = 'pete'
  const secret = Buffer.alloc(sodium.crypto_core_ed25519_UNIFORMBYTES)
  const challenge = Buffer.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  sodium.randombytes_buf(secret)
  sodium.crypto_core_ed25519_from_uniform(challenge, secret)
  server.register({ username, challenge })

  const envelope = {}
  const userPk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const userSk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(userPk, userSk)
  const userData = server.register({ username, envelope, publicKey: userPk })

  // auth begins
  const {
    envelope: retrievedEnvelope,
    publicKey,
    response
  } = server.authenticate({ userData, challenge })

  t.is(server.authentications.size, 1)
  t.is(retrievedEnvelope, envelope)
  t.is(publicKey.length, sodium.crypto_core_ed25519_BYTES)
  t.is(response.length, sodium.crypto_core_ed25519_BYTES)

  // client does some stuff with the envelope to retrieve their private key
  // and can then perform a key exchange or sign something
  const message = Buffer.alloc(8)
  const proof = Buffer.alloc(sodium.crypto_sign_BYTES + message.length)
  sodium.crypto_sign(proof, message, userSk)

  const authenticated = server.authenticate({ userData, proof })
  t.truthy(authenticated)
  t.is()
})
