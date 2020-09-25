package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"

	"github.com/pkg/errors"
)

type SignValues struct {
	R, S *big.Int
}

func ParsePrivateKey(privateKey string) (interface{}, error) {
	block, _ := pem.Decode([]byte(privateKey))

	var privKeyInterface interface{}
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		privKeyInterface, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		privKeyInterface, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privKeyInterface, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, errors.New("Unsupported key type")
	}
	if err != nil {
		return nil, errors.Wrap(err, "parse private key")
	}

	return privKeyInterface, nil
}

func NewSignature(message []byte, privKeyInterface interface{}) ([]byte, error) {
	switch privKey := privKeyInterface.(type) {
	case *ecdsa.PrivateKey:
		// Hash the message
		h := crypto.SHA256.New()
		_, _ = h.Write(message)
		hash := h.Sum(nil)

		r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
		if err != nil {
			return nil, errors.Wrap(err, "sign ecdsa")
		}

		var encBigInt SignValues
		encBigInt.R = r
		encBigInt.S = s

		signature, err := asn1.Marshal(encBigInt)
		if err != nil {
			return nil, errors.Wrap(err, "marshal ecdsa")
		}
		return signature, nil
	case *rsa.PrivateKey:
		// Hash the message
		h := crypto.SHA256.New()
		_, _ = h.Write(message)
		hash := h.Sum(nil)

		signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash)
		if err != nil {
			return nil, errors.Wrap(err, "sign pkcs1 v15")
		}
		return signature, nil
	case ed25519.PrivateKey:
		signature := ed25519.Sign(privKey, message)
		return signature, nil
	}

	return nil, errors.New("Unsupported key type")
}

func CreateSignatureAndNonceForRequest(nodeID string, data []byte, privateKey string) (string, string, error) {
	nonce, err := GenerateRandomBytes(16)
	if err != nil {
		return "", "", err
	}

	var v json.RawMessage
	err = json.Unmarshal(data, &v)
	if err != nil {
		return "", "", err
	}
	data, err = json.Marshal(v)
	if err != nil {
		return "", "", err
	}

	message := append([]byte(nodeID), []byte(data)...)
	message = append(message, []byte(nonce)...)
	signature, err := NewSignature(message, privateKey)
	if err != nil {
		return "", "", err
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)

	return signatureBase64, nonceBase64, nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}
