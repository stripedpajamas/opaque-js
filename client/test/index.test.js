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
