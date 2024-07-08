[![GoDoc](https://godoc.org/github.com/KarpelesLab/cryptutil?status.svg)](https://godoc.org/github.com/KarpelesLab/cryptutil)

# cryptutil

Some tools for handling common crypto tasks not found in the go standard library

## ECDH Message encryption

Sometimes you want to send a message. Sometimes you want it encrypted. Sending an encrypted message to a ECDSA key can be painful and come with all sorts of difficulties.

This library aims to provide a simple encryption/decryption scheme that just takes a plaintext and a key and returns an encrypted string.

The decryption function accepts any kind of ECDH handler, allowing the actual private key to be stored into a TPM or a HSM.

## Bottle

Bottles are containers for arbitrary data (json, cbor, anything) that can be used to add any number of signatures, encryption layers etc to the underlying message, while
keeping recovery of the original message fairly easy.

```go
// Create a new bottle with a message inside
bottle := cryptutil.NewBottle([]byte("s.o.s. to the world"))

// encrypt for Alice OR Bob (either will be able to open the bottle)
bottle.Encrypt(bob.Public(), alice.Public())
bottle.BottleUp() // bottle in a bottle, so that the signature includes the encryption
bottle.Sign(alice) // sign from Alice

// Bob is opening the bottle
opener, err := cryptutil.NewOpener(bob)
res, info, err := opener.Open(bottle)
// first, check err to see if opening the bottle was successful
// Then you can inspect info to see which signatures were verified, and how many
// layers of encryption were decrypted
```

## ID Card

ID Cards can be used by entities with a signing key to provide alternate encryption keys.
