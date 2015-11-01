package certificate

import (
	"crypto/x509"
	"testing"

	"github.com/chrjoh/certificateBar/key"
)

func TestCreateCertificateCahin(t *testing.T) {

	ca, caPriv := createCA()
	caPub := key.PublicKey(caPriv)
	caBytes := Sign(ca, ca, caPub, caPriv)
	interCa, interCaPriv := createInterCA()
	interCaPub := key.PublicKey(interCaPriv)
	interCaBytes := Sign(interCa, ca, interCaPub, caPriv)

	client, clientPriv := createClient()
	clientPub := key.PublicKey(clientPriv)
	clientBytes := Sign(client, interCa, clientPub, interCaPriv)
	chainOk := CheckCertificate(caBytes, interCaBytes, clientBytes)
	if !chainOk {
		t.Fatal("Failed to create certificate chain")
	}
}

func createCA() (*x509.Certificate, interface{}) {
	caData := Certificate{
		Country:            "SE",
		Organization:       "test",
		OrganizationalUnit: "WebCA",
		CA:                 true,
		SubjectKey:         []byte{1, 2, 3, 4, 5, 6},
	}

	caPriv := key.GenerateKey("P224", 0)
	return CreateCertificateTemplate(caData), caPriv
}

func createInterCA() (*x509.Certificate, interface{}) {
	interCaData := Certificate{
		Country:            "SE",
		Organization:       "test",
		OrganizationalUnit: "WebInterCA",
		CA:                 true,
		SubjectKey:         []byte{1, 2, 3},
	}
	interCaPriv := key.GenerateKey("RSA", 1024) // use small key for fast generation
	return CreateCertificateTemplate(interCaData), interCaPriv
}

func createClient() (*x509.Certificate, interface{}) {
	clientData := Certificate{
		Country:            "SE",
		Organization:       "test",
		OrganizationalUnit: "Web",
		CA:                 false,
		SubjectKey:         []byte{1, 6},
		CommonName:         "www.baz.se",
		AlternativeNames:   []string{"www.baz.se", "www.foo.se", "www.bar.se"},
	}
	clientPriv := key.GenerateKey("RSA", 1024)
	return CreateCertificateTemplate(clientData), clientPriv
}
