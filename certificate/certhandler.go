package certificate

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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

type Certificate struct {
	Country            string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	AlternativeNames   []string
	CA                 bool
	PrivateKey         interface{}
	SubjectKey         []byte
	SignatureAlg       string
}

func Sign(cert *x509.Certificate, signer *x509.Certificate, certPubKey, signerPrivateKey interface{}) []byte {
	derBytes, err := x509.CreateCertificate(rand.Reader, cert, signer, certPubKey, signerPrivateKey)
	if err != nil {
		log.Println(err)
		log.Fatalf("Failed to sign cetificate: %v\n", cert.Subject)
	}
	return derBytes
}

// NOTE:
//If an SSL certificate has a Subject Alternative Name (SAN) field, then SSL clients are supposed to ignore
//the common name value and seek a match in the SAN list.
//This is why the Cert always repeats the common name as the first SAN in the certificate.
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
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		// TODO: calculate correct subject key
		SubjectKeyId:          data.SubjectKey,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    signatureAlgorithm(data.SignatureAlg, data.PrivateKey),
		IsCA:                  data.CA,
		ExtKeyUsage:           extKeyUsage,
		KeyUsage:              keyUsage,
	}

	if data.CommonName != "" {
		cert.Subject.CommonName = data.CommonName
	}

	//TODO: handle alternative ip

	if len(data.AlternativeNames) > 0 {
		cert.DNSNames = data.AlternativeNames
		if !isStringInList(data.CommonName, data.AlternativeNames) {
			cert.DNSNames = append(cert.DNSNames, data.CommonName)
		}
	}
	return cert
}

func signatureAlgorithm(algType string, privateKey interface{}) x509.SignatureAlgorithm {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return findRsaSignALg(algType)
	case *ecdsa.PrivateKey:
		return findEcdsaSignALg(algType)
	default:
		log.Fatal("Could not find any signature algorithm\n")
		return x509.UnknownSignatureAlgorithm
	}
}

func findEcdsaSignALg(algType string) x509.SignatureAlgorithm {
	switch algType {
	case "SHA1":
		return x509.ECDSAWithSHA1
	case "SHA256":
		return x509.ECDSAWithSHA256
	case "SHA384":
		return x509.ECDSAWithSHA384
	case "SHA512":
		return x509.ECDSAWithSHA512
	default:
		return x509.ECDSAWithSHA256
	}
}

func findRsaSignALg(algType string) x509.SignatureAlgorithm {
	switch algType {
	case "SHA1":
		return x509.SHA1WithRSA
	case "SHA256":
		return x509.SHA256WithRSA
	case "SHA384":
		return x509.SHA384WithRSA
	case "SHA512":
		return x509.SHA512WithRSA
	default:
		return x509.SHA256WithRSA
	}
}

func isStringInList(value string, list []string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

func CheckCertificate(dnsName string, caBytes, interCaBytes, clientBytes []byte) bool {
	rootPool := x509.NewCertPool()
	rootCert, _ := x509.ParseCertificate(caBytes)
	rootPool.AddCert(rootCert)
	interCaPool := x509.NewCertPool()
	interCerts, _ := x509.ParseCertificates(interCaBytes)
	for _, cert := range interCerts {
		interCaPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		DNSName:       dnsName,
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
	return true
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
	fmt.Printf("wrote certificate %s to file\n", fileName)
}
