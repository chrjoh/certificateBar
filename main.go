package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

// view remote certificate
// echo |openssl s_client -connect host:443 2>/dev/null | openssl x509 -text
// view and test certificates localy
// openssl x509 -in ca.pem -text
// openssl verify -verbose -CAfile ca.pem client.pem
func main() {
	ca := createCertificateTemplate(true, []byte{1, 2, 3, 4, 5, 6}, []string{}, "SE", "test", "WebCA", "")

	caPriv, _ := rsa.GenerateKey(rand.Reader, 1024) // use small key so generation is fast
	caPub := &caPriv.PublicKey
	writePrivateKeyToPemFile(caPriv, "ca_private_key.pem")
	writePublicKeyToPemFile(caPub, "ca_public_key.pem")
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caPriv)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}
	writePemToFile(caBytes, "ca.pem")
	// test to use a certificate that is not allowed to sign as a sign certificate, checkCertificate must fail
	//interCa := createCertificateTemplate(false, []byte{1, 2, 6}, []string{}, "SE", "test", "webInterCA", "")
	interCa := createCertificateTemplate(true, []byte{1, 2, 6}, []string{}, "SE", "test", "webInterCA", "")
	interCaPriv, _ := rsa.GenerateKey(rand.Reader, 1024)
	interCaPub := &interCaPriv.PublicKey
	writePrivateKeyToPemFile(interCaPriv, "interCa_private_key.pem")
	writePublicKeyToPemFile(interCaPub, "interCa_public_key.pem")
	interCaBytes, err := x509.CreateCertificate(rand.Reader, interCa, ca, interCaPub, caPriv)
	if err != nil {
		log.Println("create interCa failed", err)
		return
	}
	writePemToFile(interCaBytes, "interCa.pem")

	client := createCertificateTemplate(false, []byte{1, 6}, []string{"www.foo.se", "www.bar.se"}, "SE", "test", "web", "www.baz.se")
	clientPriv, _ := rsa.GenerateKey(rand.Reader, 1024)
	clientPub := &clientPriv.PublicKey
	writePrivateKeyToPemFile(clientPriv, "client_private_key.pem")
	writePublicKeyToPemFile(clientPub, "client_public_key.pem")
	clientBytes, err := x509.CreateCertificate(rand.Reader, client, interCa, clientPub, interCaPriv)
	if err != nil {
		log.Println("create client failed", err)
		return
	}
	writePemToFile(clientBytes, "client.pem")
	checkCertificate(caBytes, interCaBytes, clientBytes)
}

func createCertificateTemplate(ca bool, subjectKey []byte, dnsName []string, country, org, orgUnit, cn string) *x509.Certificate {
	extKeyUsage := getExtKeyUsage(ca)
	keyUsage := getKeyUsage(ca)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{country},
			Organization:       []string{org},
			OrganizationalUnit: []string{orgUnit},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SubjectKeyId:          subjectKey,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		IsCA:                  ca,
		ExtKeyUsage:           extKeyUsage,
		KeyUsage:              keyUsage,
	}

	if !ca {
		cert.Subject.CommonName = cn
		cert.DNSNames = dnsName
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
	opts := x509.VerifyOptions{Roots: rootPool, Intermediates: interCaPool}
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

func writePrivateKeyToPemFile(key *rsa.PrivateKey, fileName string) {
	keyFile, err := os.Create(fileName)
	defer keyFile.Close()
	if err != nil {
		log.Fatalf("Failed to open %s for writing private key: %s\n", fileName, err)
	}
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	log.Printf("wrote private key %s to file\n", fileName)
}

func writePublicKeyToPemFile(key *rsa.PublicKey, fileName string) {
	keyFile, err := os.Create(fileName)
	defer keyFile.Close()
	if err != nil {
		log.Fatalf("Failed to open %s for writing public key: %s\n", fileName, err)
	}
	pubKey, _ := x509.MarshalPKIXPublicKey(key)
	pem.Encode(keyFile, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKey})
	log.Printf("wrote public key %s to file\n", fileName)
}

func writePemToFile(b []byte, fileName string) {
	certFile, err := os.Create(fileName)
	defer certFile.Close()
	if err != nil {
		log.Fatalf("Failed to open %s for writing cerificate: %s\n", fileName, err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: b})
	log.Printf("wrote certificate %s to file\n", fileName)
}
