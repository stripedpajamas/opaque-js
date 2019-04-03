/**
 * Client-side authentication flow
 *
 * Configuration:
 *   - Key exchange embedded in messages (boolean)
 *   - Perform simple signature-based auth after OPAQUE (boolean)
 *
 * 1. Send username, OPRF-alpha to server
 * 2. Receive encrypted user parameters and OPRF-beta from server
 * 3. Compute decryption key from OPRF output
 * 4. Decrypt user parameters
 * 5. Optionally perform simple signature-based auth
 */
