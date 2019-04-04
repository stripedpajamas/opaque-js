# OPAQUE

this repo houses a JavaScript implementation of the OPAQUE password authentication key exchange (PAKE) protocol.

**WARNING: this project has not been reviewed/audited for mistakes; it was created out of interest in the protocol.**

## use
see `test/integration.test.js` for how the Server and Client classes interact

the server and non-browser client implementations use [sodium](https://github.com/sodium-friends/sodium-native)
to do all the crypto functions. the interleaved key exchange is not [HMQV](https://eprint.iacr.org/2005/176.pdf)
or [SIGMA](http://webee.technion.ac.il/~hugo/sigma-pdf.pdf) as mentioned in the paper.
the built-in [key exchange functions](https://download.libsodium.org/doc/key_exchange/) from sodium
are used and then "explicit authentication" is achieved by the user sending the derived
session key to the server and the server constant-time comparing it to its own derived session key.

## todo
- [x] server registration and authentication logic
- [x] client registration and authentication logic
- [x] basic unit tests for server/client
- [x] basic integration test demonstrating how the client and server interplay
- [ ] apply iterative hash function to OPRF output to harden against offline dictionary attacks
- [ ] invalid parameter checking
- [ ] error catching/handling
- [ ] unit tests for invalid/malicious input
- [ ] browser JS client implementation using [wasm-crypto](https://github.com/jedisct1/wasm-crypto)
- [ ] basic integration test combining browser JS client with server side logic
- [ ] wrap server logic in http middleware in another package for easier plug n play
 
## references
protocol papers:
- [The OPAQUE Asymmetric PAKE Protocol (IETF)](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-01)
- [OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks (IACR)](https://eprint.iacr.org/2018/163.pdf)

other implementations:
- [@stef/libsphinx (C)](https://github.com/stef/libsphinx)
- [@cretz/gopaque (Go)](https://github.com/cretz/gopaque)
- [@noisat-labs/opaque (Rust)](https://github.com/noisat-labs/opaque)
- [@frekui/opaque (Go)](https://github.com/frekui/opaque)

## License
MIT
