`warren` is a small encryption tool that lets you encrypt files without exposing a symmetric key to plain text while also avoiding the "difficulty" of managing a private key.

Naturally, this moves the difficulty somewhere else: Password management.

`warren` provides a safe place for you to put your backups.

It generates, from a password, a public key and saves that to disk. It can then encrypt files with that public key. When it comes time to decrypt those files, you provide the original password and it recreates the private key. The intended usecase is for backups on servers that aren't fully secure from inspection.

The specific sequence of operations:  
Keygen: The string is passed through Argon2id for brute-force resistance, then into SHA3 because NaCL's GenerateKey function wants a stream of random bytes.  
Encryption: Two random keys, one for AES-256 CTR mode and one for SHA256 HMAC, are generated and boxed with NaCL's SealAnonymous function. They are used to encrypt stdin with the Zero IV (which is safe in this context due to the never-reused-key) and the HMAC is computed over the ciphertext.  
Decryption: The user provides a password which rederives the private key which is used to Open the two random keys. First the HMAC is verified and then the ciphertext is decrypted.  

It provides no versioning. Any changes to the cryptosystem or key derivation will, necessarily, be major version changes. The version in the program itself will be x.y.z, where X is incremented for breaking crypto changes, Y is incremented for breaking commandline args, and Z is incremented for bugfixes and improvements.

For instance, changing the code so that it trims off the trailing `\r\n` on Windows and trailing `\n` on Linux (so the same password creates the same key everywhere) is a breaking crypto change. Changing the existing flags would be a breaking interface change. Changing Decrypt to stream to the output file would be a Z increment because that doesn't break anything, it's just an improvement.

Because I already made some of these changes from the previous commit the program now says it is version 1.0.0.

This is my first Go program. It's probably not the most idiomatic.

Copyright (C) 2024 TomatoCo. Released under GPL 3.0.