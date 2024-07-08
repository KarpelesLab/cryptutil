# cryptutil

Some tools for handling common crypto tasks not found in the go standard library

## ECDH Message encryption

Sometimes you want to send a message. Sometimes you want it encrypted. Sending an encrypted message to a ECDSA key can be painful and come with all sorts of difficulties.

This library aims to provide a simple encryption/decryption scheme that just takes a plaintext and a key and returns an encrypted string.

The decryption function accepts any kind of ECDH handler, allowing the actual private key to be stored into a TPM or a HSM.


