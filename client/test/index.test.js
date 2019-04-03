const test = require('ava')
const sodium = require('sodium-native')
const Client = require('../src')

test('registration flow', (t) => {
  const client = new Client()
  const username = 'pete'
  const password = 'help'
  const message1 = client.register({ username, password })

  t.is(message1.username, username)
  t.is(message1.challenge.length, sodium.crypto_core_ed25519_BYTES)

  // message1 is sent to server, server generates response
  const serverOprfSecret = Buffer.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
  sodium.randombytes_buf(serverOprfSecret)
  // server sends back oprfPublicKey, serverPublicKey, response
  const response1 = {
    oprfPublicKey: Buffer.alloc(sodium.crypto_core_ed25519_BYTES),
    serverPublicKey: Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES),
    response: Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  }
  sodium.crypto_scalarmult_ed25519_base(response1.oprfPublicKey, serverOprfSecret)

  // this gets ingested by the client for the next step of registration
  const message2 = client.register(response1)

  t.is(message2.publicKey.length, sodium.crypto_kx_PUBLICKEYBYTES)
  t.is(message2.envelope.nonce.length, sodium.crypto_secretbox_NONCEBYTES)
  t.is(client.registration, null)
})

test('authentication flow', (t) => {
  const client = new Client()
  const username = 'pete'
  const password = 'help'
  const message1 = client.register({ username, password })

  t.is(message1.username, username)
  t.is(message1.challenge.length, sodium.crypto_core_ed25519_BYTES)

  // message1 is sent to server, server generates response
  const oprfSecretKey = Buffer.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
  sodium.randombytes_buf(oprfSecretKey)
  // server sends back oprfPublicKey, serverPublicKey, response
  const serverSecretKey = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
  const response1 = {
    oprfPublicKey: Buffer.alloc(sodium.crypto_core_ed25519_BYTES),
    serverPublicKey: Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES),
    response: Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  }
  sodium.crypto_kx_keypair(response1.serverPublicKey, serverSecretKey)
  sodium.crypto_scalarmult_ed25519(response1.response, oprfSecretKey, message1.challenge)
  sodium.crypto_scalarmult_ed25519_base(response1.oprfPublicKey, oprfSecretKey)
  const message2 = client.register(response1)

  // server saves message2 which is the important user data
  // along with its oprf keys
  const userData = Object.assign({}, message2, {
    oprfPublicKey: response1.oprfPublicKey,
    oprfSecretKey
  })

  // auth begins
  const authMsg1 = client.authenticate({ username, password })

  t.is(authMsg1.username, username)
  t.is(authMsg1.challenge.length, sodium.crypto_core_ed25519_BYTES)

  // server computes looks up user data and computes response
  const response = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_scalarmult_ed25519(response, oprfSecretKey, authMsg1.challenge)
  // sends back envelope, oprfPublicKey, and response to client
  const serverMsg = {
    envelope: userData.envelope,
    oprfPublicKey: userData.oprfPublicKey,
    response
  }
  const { userSession } = client.authenticate(serverMsg)

  t.is(client.authentication, null)
  t.is(userSession.length, sodium.crypto_kx_SESSIONKEYBYTES)
})
