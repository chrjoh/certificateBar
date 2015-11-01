package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/chrjoh/certificateBar/key"
)

var (
	OU = asn1.ObjectIdentifier{2, 5, 4, 11}
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

	clientCert, _ := x509.ParseCertificate(clientBytes)
	ouIssuer := getPkixValue(clientCert.Issuer.Names, OU)
	if ouIssuer != "WebInterCA" {
		t.Fatalf("Wrong issuer ou wanted: WebInterCA, got: %v\n", ouIssuer)
	}
	interCert, _ := x509.ParseCertificate(interCaBytes)
	ouIssuer = getPkixValue(interCert.Issuer.Names, OU)
	if ouIssuer != "WebCA" {
		t.Fatalf("Wrong issuer ou wanted: WebCA, got: %v\n", ouIssuer)
	}
	caCert, _ := x509.ParseCertificate(caBytes)
	ouIssuer = getPkixValue(caCert.Issuer.Names, OU)
	if ouIssuer != "WebCA" {
		t.Fatalf("Wrong issuer ou wanted: WebCA, got: %v\n", ouIssuer)
	}
}

func TestValidSignedCertificateCahin(t *testing.T) {

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

func getPkixValue(values []pkix.AttributeTypeAndValue, key asn1.ObjectIdentifier) string {
	for _, v := range values {
		if v.Type.Equal(key) {
			return v.Value.(string)
		}
	}
	return ""
}
