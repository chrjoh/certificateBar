package assembler

import "crypto/x509"

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
	Pkix      PkixData `yaml:"pkix"`
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
