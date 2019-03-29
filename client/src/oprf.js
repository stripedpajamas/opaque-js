/**
 * Client-side OPRF logic
 * 
 * DH-OPRF should have:
 *   - H: hash function
 *   - G: cyclic group of prime order q
 *   - g: generator of G
 *   - Hp: hash function mapping arbitrary strings into G
 * 
 * 1. Choose random r in [0..q-1]; PwdU is function input
 * 2. Compute alpha and send to server
 * 3. Receive beta and vU from server
 * 4. Compute OPRF output = H(PwdU, vU, beta*v^{-r})
 */
