package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/chrjoh/certificateBar/key"
)

var (
	OU = asn1.ObjectIdentifier{2, 5, 4, 11}
)
var pemPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
+QIDAQAB
-----END PUBLIC KEY-----
`

func TestSubjectKeyId(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPublicKey))
	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	data := keyIdentifier(pub)
	s := hex.EncodeToString(data)
	if s != "103cb6fde54563169f15f5eecd414506410a77ad" {
		t.Fatalf("Wrong subjectKeyId, got: %s, wanted: 103cb6fde54563169f15f5eecd414506410a77ad", s)
	}
}

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
	for _, name := range []string{"", "www.baz.se", "www.foo.se", "www.bar.se"} {
		chainOk := CheckCertificate(name, caBytes, interCaBytes, clientBytes)
		if !chainOk {
			t.Fatalf("Failed to verify client for dnsName: ", name)
		}
	}
}
func createCA() (*x509.Certificate, interface{}) {
	caPriv := key.GenerateKey("RSA", 1024)
	caData := Certificate{
		Id:                 "one",
		Country:            "SE",
		Organization:       "test",
		OrganizationalUnit: "WebCA",
		CA:                 true,
		PrivateKey:         caPriv,
	}

	return CreateCertificateTemplate(caData), caPriv
}

func createInterCA() (*x509.Certificate, interface{}) {
	interCaPriv := key.GenerateKey("RSA", 1024) // use small key for fast generation
	interCaData := Certificate{
		Id:                 "two",
		Country:            "SE",
		Organization:       "test",
		OrganizationalUnit: "WebInterCA",
		CA:                 true,
		PrivateKey:         interCaPriv,
	}
	return CreateCertificateTemplate(interCaData), interCaPriv
}

func createClient() (*x509.Certificate, interface{}) {
	clientPriv := key.GenerateKey("RSA", 1024)
	clientData := Certificate{
		Id:                 "three",
		Country:            "SE",
		Organization:       "test",
		OrganizationalUnit: "Web",
		CA:                 false,
		CommonName:         "www.baz.se",
		AlternativeNames:   []string{"www.foo.se", "www.bar.se"},
		PrivateKey:         clientPriv,
	}
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
