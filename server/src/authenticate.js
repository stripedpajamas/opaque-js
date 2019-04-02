/**
 * Server-side authentication flow
 *
 * Configuration:
 *   - Key exchange embedded in messages (boolean)
 *   - Perform simple signature-based auth after OPAQUE (boolean)
 *
 * 1. Receive username, OPRF-alpha from client
 * 2. Retrieve user parameters from storage
 * 3. Compute OPRF-beta
 * 4. Send user parameters EnvU, vU and OPRF-beta to client
 * 5. Optionally perform simple signature-based auth
 */
