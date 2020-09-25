package kms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/pkg/errors"
)

func TestSigning(t *testing.T) {
	pri, pub, err := pairingKey()
	if err != nil {
		t.Error(err)
		return
	}

	privKeyInterface, _ := ParsePrivateKey(string(pri))

	message := "test test test"
	signed, err := NewSignature([]byte(message), privKeyInterface)
	if err != nil {
		t.Error(err)
		return
	}

	err = verifySignature(string(pub), signed, []byte(message))

	if err != nil {
		t.Error(err)
	}
}

func TestSigningRSA(t *testing.T) {
	pri, pub, err := pairingKey()
	if err != nil {
		t.Error(err)
		return
	}

	message := []byte("test test test")

	h := crypto.SHA256.New()
	_, _ = h.Write(message)
	hash := h.Sum(nil)

	block, _ := pem.Decode([]byte(pri))

	privKeyInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Error(err)
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKeyInterface, crypto.SHA256, hash)
	if err != nil {
		t.Error(err)
	}

	block, _ = pem.Decode([]byte(pub))
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Error(err)
	}

	err = rsa.VerifyPKCS1v15(publicKeyInterface.(*rsa.PublicKey), crypto.SHA256, hash, signature)
	if err != nil {
		t.Error(err)
	}

}

func verifySignature(publicKey string, signature []byte, message []byte) error {
	block, _ := pem.Decode([]byte(publicKey))

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "parse PKIX public")
	}

	switch pubKey := publicKeyInterface.(type) {
	case *ecdsa.PublicKey:
		// Hash the message
		h := crypto.SHA256.New()
		if _, err := h.Write(message); err != nil {
			return errors.WithStack(err)
		}
		hash := h.Sum(nil)

		var signVal signValues
		_, err = asn1.Unmarshal(signature, &signVal)
		if err != nil {
			return errors.Wrap(err, "ecdsa signature")
		}

		if !ecdsa.Verify(pubKey, hash, signVal.R, signVal.S) {
			return errors.New("invalid ecdsa signature")
		}
		return nil
	case *rsa.PublicKey:
		// Hash the message
		h := crypto.SHA256.New()
		if _, err := h.Write(message); err != nil {
			return errors.WithStack(err)
		}
		hash := h.Sum(nil)

		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash, signature)
		if err != nil {
			if err.Error() == rsa.ErrDecryption.Error() ||
				err.Error() == rsa.ErrMessageTooLong.Error() ||
				err.Error() == rsa.ErrVerification.Error() {
				return errors.Wrap(err, "rsa signature")
			}
			return err
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pubKey, message, signature) {
			return errors.New("ed25519 signature")
		}
		return nil
	}

	return errors.New("Unsupported key type")
}

type signValues struct {
	R, S *big.Int
}

func pairingKey() ([]byte, []byte, error) {
	// Generate key pair
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	privateKeyPEM := new(bytes.Buffer)

	err = pem.Encode(privateKeyPEM, privateKey)
	if err != nil {
		return nil, nil, err
	}
	//

	// Write public key to file
	asn1Bytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	var publicKey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	publicKeyPEM := new(bytes.Buffer)

	err = pem.Encode(publicKeyPEM, publicKey)

	return privateKeyPEM.Bytes(), publicKeyPEM.Bytes(), err
}
