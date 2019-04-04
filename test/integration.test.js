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

  // client wants to authenticate
  clientMessage1 = client.authenticate({ username, password })
  // server looks up username in DB to find userData
  // and then continues
  serverMessage1 = server.authenticate({
    userData,
    ...clientMessage1
  })
  clientMessage2 = client.authenticate(serverMessage1)
  const authenticated = server.authenticate({
    userData,
    ...clientMessage2
  })

  t.is(authenticated, true) // 🎉 🎉 🎉
})
