package cryptutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
)

type ECDHHandler interface {
	ECDH(remote *ecdh.PublicKey) ([]byte, error)
}

// ECDHEncrypt encrypts data for receiving by remote
func ECDHEncrypt(data []byte, remote *ecdh.PublicKey, rnd io.Reader) ([]byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	priv, err := remote.Curve().GenerateKey(rnd)
	if err != nil {
		return nil, err
	}

	secret, err := priv.ECDH(remote)
	if err != nil {
		return nil, err
	}

	defer MemClr(secret)
	secretHash := Hash(secret, sha256.New)
	defer MemClr(secretHash)

	pub, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}

	algo, err := aes.NewCipher(secretHash)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(algo)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	// format: <version=0><ecdsa key len><ephemeral ecdsa public key><nonce><data>
	final := &bytes.Buffer{}
	final.WriteByte(0) // version
	final.Write(binary.AppendUvarint(nil, uint64(len(pub))))
	final.Write(pub)
	final.Write(nonce)
	final.Write(gcm.Seal(nil, nonce, data, nil))

	return final.Bytes(), nil
}

// ECDHDecrypt decrypts data received for us, using the private key passed (can be a tpm, etc)
func ECDHDecrypt(data []byte, privateKey ECDHHandler) ([]byte, error) {
	e := func(err error) error {
		if err == nil {
			return nil
		}
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("while decrypting ECDH message: %w", err)
	}

	buf := bytes.NewReader(data)
	vers, err := buf.ReadByte()
	if err != nil {
		return nil, e(err)
	}
	switch vers {
	case 0:
		// format: <version=0><ecdsa key len><ephemeral ecdsa public key><nonce><data>
		ln, err := binary.ReadUvarint(buf)
		if err != nil {
			return nil, e(err)
		}
		if ln > 65536 {
			return nil, fmt.Errorf("public key too large: %d bytes", ln)
		}
		// pubkey is the ephemeral encryption key
		pubkey := make([]byte, ln)
		_, err = io.ReadFull(buf, pubkey)
		if err != nil {
			return nil, e(err)
		}
		pubkeyObj, err := x509.ParsePKIXPublicKey(pubkey)
		if err != nil {
			return nil, e(err)
		}
		var pubECDH *ecdh.PublicKey
		switch v := pubkeyObj.(type) {
		case *ecdsa.PublicKey:
			pubECDH, err = v.ECDH()
			if err != nil {
				return nil, e(err)
			}
		case *ecdh.PublicKey:
			pubECDH = v
		default:
			return nil, fmt.Errorf("unsupported public key type %T", v)
		}
		secret, err := privateKey.ECDH(pubECDH)
		if err != nil {
			return nil, e(err)
		}
		defer MemClr(secret)
		secretHash := Hash(secret, sha256.New)
		defer MemClr(secretHash)

		algo, err := aes.NewCipher(secretHash)
		if err != nil {
			return nil, e(err)
		}

		gcm, err := cipher.NewGCM(algo)
		if err != nil {
			return nil, e(err)
		}

		nonce := make([]byte, gcm.NonceSize())
		_, err = io.ReadFull(buf, nonce)
		if err != nil {
			return nil, e(err)
		}

		dat, err := io.ReadAll(buf)
		if err != nil {
			return nil, e(err)
		}

		return gcm.Open(dat[:0], nonce, dat, nil)
	default:
		return nil, fmt.Errorf("unsupported message version %d", vers)
	}
}
