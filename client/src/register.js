/**
 * Client-side registration flow
 * 
 * 1. Send username to server
 * 2. Generate keypair
 * 3. Perform OPRF flow with password as input
 * 4. Encrypt keypair and server public key using OPRF output as key
 * 5. Send encrypted parameters and public key to server
 */
