`warren` is a small encryption tool that lets you encrypt files without exposing a symmetric key to plain text while also avoiding the "difficulty" of managing a private key.

Naturally, this moves the difficulty somewhere else: Password management.

`warren` is part of making a safe place to keep your files.

It generates, from a password, a public key and saves that to disk. It can then encrypt files with that public key. When it comes time to decrypt those files, you provide the original password and it recreates the private key. The intended usecase is for backups on servers that aren't fully secure from inspection.

The specific sequence of operations:  
Keygen: The string is passed through Argon2id for brute-force resistance, then into SHA3 because NaCL's GenerateKey function wants a stream of random bytes.  
Encryption: Two random keys, one for AES-256 CTR mode and one for SHA256 HMAC, are generated and boxed with NaCL's SealAnonymous function. They are used to encrypt stdin with the Zero IV (which is safe in this context due to the never-reused-key) and the HMAC is computed over the ciphertext.  
Decryption: The user provides a password which rederives the private key which is used to Open the two random keys. First the HMAC is verified and then the ciphertext is decrypted.  

It provides no versioning. Any changes to the cryptosystem or key derivation will, necessarily, be major version changes.  

This is my first Go program. It's probably not the most idiomatic.