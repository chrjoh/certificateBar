package assembler

import (
	"crypto/x509"
	"time"
)

type PkixData struct {
	CommonName       string `yaml:"commonname"`
	Country          string `yaml:"country"`
	Organization     string `yaml:"organization"`
	OrganizationUnit string `yaml:"organizationunit"`
}

type CertData struct {
	Id        string   `yaml:"id"`
	CA        bool     `yaml:"ca"`
	Parent    string   `yaml:"parent"`
	KeyType   string   `yaml:"keytype"`
	KeyLength int      `yaml:"keylength"`
	HashAlg   string   `yaml:"hashalg"`
	AltNames  []string `yaml:"altnames"`
	DateFrom  string   `yaml:"validfrom"`
	DateTo    string   `yaml:"validto"`
	Pkix      PkixData `yaml:"pkix"`
	Usage     []string `yaml:"usage"`
}

type Cert struct {
	CertConfig   CertData `yaml:"certificate"`
	signed       bool
	toBeUsed     bool
	PrivateKey   interface{}
	CertTemplate *x509.Certificate
	CertBytes    []byte
	Signers      []string
}

type Certs struct {
	Certificates []*Cert `yaml:"certificates"`
	certSigners  map[string][]string
}

func (cd *CertData) ValidFrom() time.Time {
	if cd.DateFrom == "" {
		return time.Now()
	}
	tt, _ := time.Parse("2006-01-02", cd.DateFrom)
	return tt
}

func (cd *CertData) ValidTo() time.Time {
	if cd.DateTo == "" {
		return time.Now().AddDate(1, 0, 0)
	}
	tt, _ := time.Parse("2006-01-02", cd.DateTo)
	return tt
}
