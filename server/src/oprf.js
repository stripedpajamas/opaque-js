/**
 * Server-side OPRF logic
 * 
 * DH-OPRF should have:
 *   - H: hash function
 *   - G: cyclic group of prime order q
 *   - g: generator of G
 *   - Hp: hash function mapping arbitrary strings into G
 * 
 * 1. Receive alpha from client, kU is function input
 * 2. Compute vU = g^kU, beta = alpha^kU
 * 3. Send vU, beta to client
 */
