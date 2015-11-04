package key

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestPublicRSAKey(t *testing.T) {
	k := GenerateKey("RSA", 1024).(*rsa.PrivateKey)
	if reflect.TypeOf(PublicKey(k)) != reflect.TypeOf((*rsa.PublicKey)(nil)) {
		t.Fatalf("got: %v, want %v", reflect.TypeOf(PublicKey(k)), reflect.TypeOf((*rsa.PublicKey)(nil)))
	}
}

func TestPublicECDSAKey(t *testing.T) {
	k := GenerateKey("P224", 0).(*ecdsa.PrivateKey)
	if reflect.TypeOf(PublicKey(k)) != reflect.TypeOf((*ecdsa.PublicKey)(nil)) {
		t.Fatalf("got: %v, want %v", reflect.TypeOf(PublicKey(k)), reflect.TypeOf((*ecdsa.PublicKey)(nil)))
	}
}
