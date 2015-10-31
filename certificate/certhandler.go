package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/chrjoh/certificateBar/key"
)

// view remote certificate
// echo |openssl s_client -connect host:443 2>/dev/null | openssl x509 -text
// view and test certificates localy
// openssl x509 -in ca.pem -text
// openssl verify -verbose -CAfile ca.pem client.pem

type Certificate struct {
	Country            string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	AlternativeNames   []string
	CA                 bool
	SubjectKey         []byte
}

func Handler() {

	ca, caPriv := createCA()
	caPub := key.PublicKey(caPriv)
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caPriv)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}
	WritePemToFile(caBytes, "ca.pem")
	// test to use a certificate that is not allowed to sign as a sign certificate, checkCertificate must fail
	// set CA to false for this check on inteCA cert
	interCa, interCaPriv := createInterCA()
	interCaPub := key.PublicKey(interCaPriv)
	interCaBytes, err := x509.CreateCertificate(rand.Reader, interCa, ca, interCaPub, caPriv)
	if err != nil {
		log.Println("create interCa failed", err)
		return
	}
	WritePemToFile(interCaBytes, "interCa.pem")

	client, clientPriv := createClient()
	clientPub := key.PublicKey(clientPriv)
	clientBytes, err := x509.CreateCertificate(rand.Reader, client, interCa, clientPub, interCaPriv)
	if err != nil {
		log.Println("create client failed", err)
		return
	}
	WritePemToFile(clientBytes, "client.pem")
	checkCertificate(caBytes, interCaBytes, clientBytes)
}

func Sign(cert *x509.Certificate, signer *x509.Certificate, certPubKey, signerPrivateKey interface{}) []byte {
	derBytes, err := x509.CreateCertificate(rand.Reader, cert, signer, certPubKey, signerPrivateKey)
	if err != nil {
		log.Println(err)
		log.Fatalf("Failed to sign cetificate: %v\n", cert.Subject)
	}
	return derBytes
}

func createCA() (*x509.Certificate, interface{}) {
	caData := Certificate{
		Country:            "SE",
		Organization:       "test",
		OrganizationalUnit: "WebCA",
		CA:                 true,
		SubjectKey:         []byte{1, 2, 3, 4, 5, 6},
	}

	caPriv := key.GenerateKey("P224", 0) // use small key so generation is fast
	caPub := key.PublicKey(caPriv)
	key.WritePrivateKeyToPemFile(caPriv, "ca_private_key.pem")
	key.WritePublicKeyToPemFile(caPub, "ca_public_key.pem")
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
	interCaPriv := key.GenerateKey("RSA", 1024)
	interCaPub := key.PublicKey(interCaPriv)
	key.WritePrivateKeyToPemFile(interCaPriv, "interCa_private_key.pem")
	key.WritePublicKeyToPemFile(interCaPub, "interCa_public_key.pem")
	return CreateCertificateTemplate(interCaData), interCaPriv
}

// NOTE:
//If an SSL certificate has a Subject Alternative Name (SAN) field, then SSL clients are supposed to ignore
//the common name value and seek a match in the SAN list.
//This is why the Cert always repeats the common name as the first SAN in the certificate.
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
	clientPub := key.PublicKey(clientPriv)
	key.WritePrivateKeyToPemFile(clientPriv, "client_private_key.pem")
	key.WritePublicKeyToPemFile(clientPub, "client_public_key.pem")
	return CreateCertificateTemplate(clientData), clientPriv
}

func CreateCertificateTemplate(data Certificate) *x509.Certificate {
	extKeyUsage := getExtKeyUsage(data.CA)
	keyUsage := getKeyUsage(data.CA)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{data.Country},
			Organization:       []string{data.Organization},
			OrganizationalUnit: []string{data.OrganizationalUnit},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SubjectKeyId:          data.SubjectKey,
		BasicConstraintsValid: true,
		// need to use different sig. alg for different key types
		//		SignatureAlgorithm:    x509.SHA256WithRSA,
		IsCA:        data.CA,
		ExtKeyUsage: extKeyUsage,
		KeyUsage:    keyUsage,
	}

	if data.CommonName != "" {
		cert.Subject.CommonName = data.CommonName
	}
	if len(data.AlternativeNames) > 0 {
		cert.DNSNames = data.AlternativeNames
	}
	return cert
}

func checkCertificate(caBytes, interCaBytes, clientBytes []byte) {
	rootPool := x509.NewCertPool()
	rootCert, _ := x509.ParseCertificate(caBytes)
	rootPool.AddCert(rootCert)
	interCaPool := x509.NewCertPool()
	interCerts, _ := x509.ParseCertificates(interCaBytes)
	for _, cert := range interCerts {
		interCaPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		DNSName:       "www.baz.se",
		Roots:         rootPool,
		Intermediates: interCaPool,
	}
	clientCert, _ := x509.ParseCertificate(clientBytes)
	_, certErr := clientCert.Verify(opts)
	if certErr != nil {
		log.Println(certErr)
		os.Exit(1)
	}
	log.Println("Certificates verify: OK")
}
func getKeyUsage(ca bool) x509.KeyUsage {
	if ca {
		return x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	}
	return x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
}

func getExtKeyUsage(ca bool) []x509.ExtKeyUsage {
	if ca {
		return []x509.ExtKeyUsage{}
	}
	return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
}

func WritePemToFile(b []byte, fileName string) {
	certFile, err := os.Create(fileName)
	defer certFile.Close()
	if err != nil {
		log.Fatalf("Failed to open %s for writing cerificate: %s\n", fileName, err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: b})
	log.Printf("wrote certificate %s to file\n", fileName)
}
