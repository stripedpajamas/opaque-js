const test = require('ava')
const sodium = require('sodium-native')
const Server = require('../src')

test('init creates a keypair if none passed in', (t) => {
  const server = new Server()
  t.is(server.config.pk.length, sodium.crypto_kx_PUBLICKEYBYTES, 'pk correct length')
  t.is(server.config.sk.length, sodium.crypto_kx_SECRETKEYBYTES, 'sk correct length')
})

test('registration flow', (t) => {
  const server = new Server()

  const username = 'pete'
  const secret = Buffer.alloc(sodium.crypto_core_ed25519_UNIFORMBYTES)
  const challenge = Buffer.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  sodium.randombytes_buf(secret)
  sodium.crypto_core_ed25519_from_uniform(challenge, secret)
  const {
    hashOpsLimit,
    hashMemLimit,
    hashSalt,
    oprfPublicKey,
    serverPublicKey,
    response
  } = server.register({ username, challenge })

  t.is(server.registrations.size, 1)
  t.is(serverPublicKey.length, sodium.crypto_kx_PUBLICKEYBYTES)
  t.is(oprfPublicKey.length, sodium.crypto_core_ed25519_BYTES)
  t.is(response.length, sodium.crypto_core_ed25519_BYTES)

  // hardening params
  t.is(typeof hashOpsLimit, 'number')
  t.is(typeof hashMemLimit, 'number')
  t.is(hashSalt.length, sodium.crypto_pwhash_SALTBYTES)

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
  const userPk = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
  const userSk = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
  sodium.crypto_kx_keypair(userPk, userSk)
  const userData = server.register({ username, envelope, publicKey: userPk })

  // auth begins
  const {
    envelope: retrievedEnvelope,
    oprfPublicKey,
    response
  } = server.authenticate({ userData, challenge })

  t.is(server.authentications.size, 1)
  t.is(retrievedEnvelope, envelope)
  t.is(oprfPublicKey.length, sodium.crypto_core_ed25519_BYTES)
  t.is(response.length, sodium.crypto_core_ed25519_BYTES)

  // client does some stuff with the envelope to retrieve their private key
  // and can then perform a key exchange
  const userSession = Buffer.alloc(sodium.crypto_kx_SESSIONKEYBYTES)
  sodium.crypto_kx_client_session_keys(userSession, null, userPk, userSk, server.config.pk)

  const authenticated = server.authenticate({ userData, userSession })
  t.truthy(authenticated)
  t.is(server.authentications.size, 0)
})
