package assembler

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestReadConfigFile(t *testing.T) {
	marshalCertData(t)
}

func TestKeySetup(t *testing.T) {
	test := marshalCertData(t)
	test.setupKeys()
	for _, c := range test.Certificates {
		if c.PrivateKey == nil {
			t.Fatalf("Cert %v did not get a private key", c.CertConfig.Id)
		}
		if c.CertConfig.Id == "mainca" {
			if reflect.TypeOf(c.PrivateKey) != reflect.TypeOf((*ecdsa.PrivateKey)(nil)) {
				t.Fatalf("got: %v, want %v", reflect.TypeOf(c.PrivateKey), reflect.TypeOf((*ecdsa.PrivateKey)(nil)))
			}
		} else {
			if reflect.TypeOf(c.PrivateKey) != reflect.TypeOf((*rsa.PrivateKey)(nil)) {
				t.Fatalf("got: %v, want %v", reflect.TypeOf(c.PrivateKey), reflect.TypeOf((*rsa.PrivateKey)(nil)))
			}
		}
	}
}
func TestSignAll(t *testing.T) {
	test := marshalCertData(t)
	test.setupKeys()
	test.setupTemplates()
	test.setupSigner()
	test.signAll()
	for _, cert := range test.Certificates {
		if !cert.signed {
			if cert.CertConfig.Id != "client3" {
				t.Fatalf("Failed to sign cert: %v", cert.CertConfig.Id)
			}
		}
	}
}

func TestInitialSigner(t *testing.T) {
	test := marshalCertData(t)
	test.setupKeys()
	test.setupTemplates()
	test.setupSigner()
}

func TestTemplateSetup(t *testing.T) {
	test := marshalCertData(t)
	test.setupTemplates()
}

func marshalCertData(t *testing.T) Certs {
	test := Certs{}
	data := ReadFile("_fixtures/data.yaml")
	err := yaml.Unmarshal(data, &test)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	return test
}
