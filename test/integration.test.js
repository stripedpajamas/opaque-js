const test = require('ava')
const Server = require('../server')
const Client = require('../client')

test('full flow', (t) => {
  const server = new Server()
  const client = new Client()

  const username = 'pete'
  const password = 'help'

  let clientMessage1 = client.register({ username, password })
  let serverMessage1 = server.register(clientMessage1)
  let clientMessage2 = client.register(serverMessage1)
  const userData = server.register(clientMessage2)

  // userData is to be persisted on the server
  // the user is now considered registered
  const expectedFields = [
    'username',
    'envelope',
    'userPublicKey',
    'oprfPublicKey',
    'oprfSecretKey'
  ]
  for (let field of expectedFields) {
    t.not(typeof userData[field], 'undefined')
  }
})
