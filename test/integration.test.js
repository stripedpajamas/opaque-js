const test = require('ava')
const Server = require('../server')
const Client = require('../client')

test('full flow', (t) => {
  const server = new Server()
  const client = new Client()

  const username = 'pete'
  const password = 'help'

  let clientMessage1 = client.beginRegistration({ username, password })
  let serverMessage1 = server.beginRegistration(clientMessage1)
  let clientMessage2 = client.finishRegistration(serverMessage1)
  const userData = server.finishRegistration(clientMessage2)

  // userData is to be persisted on the server
  // the user is now considered registered

  // client wants to authenticate
  clientMessage1 = client.beginAuthentication({ username, password })
  // server looks up username in DB to find userData
  // and then continues
  serverMessage1 = server.beginAuthentication({
    userData,
    ...clientMessage1
  })
  clientMessage2 = client.finishAuthentication(serverMessage1)
  let authenticated = server.finishAuthentication({
    userData,
    ...clientMessage2
  })

  t.is(authenticated, true) // 🎉 🎉 🎉

  // try again with an invalid password
  clientMessage1 = client.beginAuthentication({ username, password: 'wrong' })
  serverMessage1 = server.beginAuthentication({
    userData,
    ...clientMessage1
  })
  clientMessage2 = client.finishAuthentication(serverMessage1)
  authenticated = server.finishAuthentication({
    userData,
    ...clientMessage2
  })

  t.is(authenticated, false) // 🔒 🔒 🔒
})
