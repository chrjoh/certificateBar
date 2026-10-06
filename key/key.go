package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
)

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

func PublicKey(privateKey interface{}) interface{} {
	var publicKey interface{}
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	default:
		log.Fatal("Could not get public key\n")
		return publicKey
	}
}

func PublicKeyBitArray(pub interface{}) (publicKeyBytes []byte, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	default:
		return nil, errors.New("x509: only RSA and ECDSA public keys supported")
	}
	return publicKeyBytes, nil
}

// TODO: use struct for this so that we do not have unused arguments
func GenerateKey(keyType string, rsaBitLength int) interface{} {
	var privateKey interface{}
	var err error
	switch keyType {
	case "RSA":
		privateKey, err = rsa.GenerateKey(rand.Reader, rsaBitLength)
	case "P224":
		privateKey, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Fatalf("Unrecognized key type: %v", keyType)
	}
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}
	return privateKey
}

// EncodePrivateKeyPem returns the private key in pem form.
func EncodePrivateKeyPem(key interface{}) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), nil
	case *ecdsa.PrivateKey:
		ecKey, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKey}), nil
	default:
		return nil, fmt.Errorf("unknown key type %T to write to file", key)
	}
}

// ReadPrivateKeyFromPemFile reads back a key written in the form of EncodePrivateKeyPem
// so that an existing certificate can keep signing with the very same key.
func ReadPrivateKeyFromPemFile(fileName string) (interface{}, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file %s: %v", fileName, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no pem data found in private key file: %s", fileName)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type %v in file: %s", block.Type, fileName)
	}
}
