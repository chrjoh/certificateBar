package assembler

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/chrjoh/certificateBar/certificate"

	"gopkg.in/yaml.v2"
)

func TestReadConfigFile(t *testing.T) {
	test := marshalCertData("_fixtures/one_cert.yaml", t)
	c := test.Certificates[0].CertConfig
	if !c.CA {
		t.Fatalf("wanted: true, got:", c.CA)
	}
	if c.KeyType != "P224" {
		t.Fatalf("wanted: P224, got:", c.KeyType)
	}
	if c.Pkix.CommonName != "www.foo.se" {
		t.Fatalf("wanted: www.foo.se, got:", c.Pkix.CommonName)
	}
	if c.ValidFrom().String() != "2015-11-01 00:00:00 +0000 UTC" {
		t.Fatalf("wanted: 2015-11-01 00:00:00 +0000 UTC, got:", c.ValidFrom())
	}
}

func TestUsage(t *testing.T) {
	test := marshalCertData("_fixtures/one_cert.yaml", t)
	c := test.Certificates[0].CertConfig
	if len(c.Usage) != 4 {
		t.Fatal("failed to find any certificate usage")
	}
	for _, u := range c.Usage {
		if !containsAny(u, "certsign", "crlsign", "serverauth", "clientauth") {
			t.Fatalf("Failed to find '%v' in the usage list", u)
		}
	}
}

func TestKeySetup(t *testing.T) {
	test := marshalCertData("_fixtures/data.yaml", t)
	test.setupKeys()
	for _, c := range test.Certificates {
		if c.CertConfig.Id == "maincaecdsa" || c.CertConfig.Id == "clientecdsa" {
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
	test := marshalCertData("_fixtures/data.yaml", t)
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
	client, _ := test.findByid("client")
	ca, _ := test.findByid(client.Signers[0])
	inca, _ := test.findByid(client.Signers[1])
	result := certificate.CheckCertificate("", ca.CertBytes, inca.CertBytes, client.CertBytes)
	if !result {
		t.Fatal("certificate with id: client did not have correct certificate chain")
	}
}

func TestInitialSigner(t *testing.T) {
	test := marshalCertData("_fixtures/data.yaml", t)
	test.setupKeys()
	test.setupTemplates()
	test.setupSigner()
	for _, v := range test.Certificates {
		if (v.CertConfig.Id == "mainca" || v.CertConfig.Id == "maincaecdsa") && !v.signed {
			t.Fatalf("selfsigned certificate %v was not signed", v.CertConfig.Id)
		}
		if !(v.CertConfig.Id == "mainca" || v.CertConfig.Id == "maincaecdsa") && v.signed {
			t.Fatalf("non root cert %v was signed", v.CertConfig.Id)
		}
	}
}

func TestTemplateSetup(t *testing.T) {
	test := marshalCertData("_fixtures/data.yaml", t)
	test.setupKeys()
	test.setupTemplates()
	for _, v := range test.Certificates {
		if v.CertTemplate == nil {
			t.Fatalf("Failed to create template for: %v", v.CertConfig.Id)
		}
	}
}

func TestFindById(t *testing.T) {
	test := marshalCertData("_fixtures/data.yaml", t)
	cert, _ := test.findByid("client")
	ou := cert.CertConfig.Pkix.OrganizationUnit
	if ou != "testweb" {
		t.Fatalf("Failed to cert got: %v wanted: testweb", ou)
	}
}

func marshalCertData(filename string, t *testing.T) Certs {
	test := Certs{}
	data := readFile(filename)
	err := yaml.Unmarshal(data, &test)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	return test
}

func containsAny(s string, valid ...string) bool {
	result := make(map[string]struct{})
	for _, v := range valid {
		result[v] = struct{}{}
	}
	_, ok := result[s]

	return ok
}
