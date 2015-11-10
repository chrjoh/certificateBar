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

func WritePrivateKeyToPemFile(key interface{}, fileName string) {
	keyFile, err := os.Create(fileName)
	defer keyFile.Close()
	if err != nil {
		log.Fatalf("Failed to open %s for writing private key: %s\n", fileName, err)
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		fmt.Printf("wrote RSA private key %s to file\n", fileName)
	case *ecdsa.PrivateKey:
		ecKey, _ := x509.MarshalECPrivateKey(k)
		pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKey})
		fmt.Printf("wrote EC private key %s to file\n", fileName)
	default:
		log.Printf("Uknown key type: %v to write to file", key)
	}
}

func WritePublicKeyToPemFile(key interface{}, fileName string) {
	keyFile, err := os.Create(fileName)
	defer keyFile.Close()
	if err != nil {
		log.Fatalf("Failed to open %s for writing public key: %s\n", fileName, err)
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		pubKey, _ := x509.MarshalPKIXPublicKey(k)
		pem.Encode(keyFile, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKey})
		log.Printf("wrote RSA private key %s to file\n", fileName)
	case *ecdsa.PublicKey:
		log.Printf("EC public key is stored then writting the private part\n")
	default:
		log.Printf("Uknown key type: %v to write to file", key)
	}
}
