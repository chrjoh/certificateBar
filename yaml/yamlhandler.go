package yaml

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
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
	Pkix      PkixData `yaml:"pkix"`
}

type Cert struct {
	CertConfig   CertData `yaml:"certificate"`
	signed       bool
	toBeUsed     bool
	PrivateKey   rsa.PrivateKey
	CertTemplate x509.Certificate
	CertBytes    []byte
	Signers      []string
}

type Certs struct {
	Certificates []*Cert `yaml:"certificates"`
	certSigners  map[string][]string
}

func Handler() {
	test := Certs{}
	data := ReadFile("./config/data.yaml")
	err := yaml.Unmarshal(data, &test)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	test.setupSigner()
	test.signAll()
	//	fmt.Printf("--- test:\n%v\n\n", test)

}
func (c *Certs) setupSigner() {
	c.certSigners = make(map[string][]string)
	for _, val := range c.Certificates {
		key := val.CertConfig.Parent
		id := val.CertConfig.Id
		if key == id {
			val.signed = true // perform selfSign
		} else if c.certSigners[key] == nil {
			c.certSigners[key] = []string{id}
		} else {
			c.certSigners[key] = append(c.certSigners[key], id)
		}
	}
}

func (c *Certs) signAll() {
	for {
		sign := findSigners(c)
		if len(sign) == 0 {
			break
		}
		for _, s := range sign {
			id := s.CertConfig.Id
			list := c.certSigners[id]
			for _, certId := range list {
				fmt.Printf("%v is Sign: %s\n", id, certId)
				for _, cert := range c.Certificates {
					if cert.CertConfig.Id == certId {
						// sign certificate method
						cert.signed = true
						if s.Signers == nil {
							cert.Signers = []string{id}
						} else {
							cert.Signers = append(s.Signers, id)
						}
						break
					}
				}
			}
		}
	}
	for _, cert := range c.Certificates {
		if len(cert.Signers) > 0 {
			fmt.Printf("Cert: %s, has certificate chain: %v\n", cert.CertConfig.Id, strings.Join(cert.Signers, ", "))
		}
		if !cert.signed {
			fmt.Printf("Failed to sign: %s\n", cert.CertConfig.Id)
		}
	}
}

func findSigners(c *Certs) []*Cert {
	sign := []*Cert{}
	for _, val := range c.Certificates {
		if val.signed && !val.toBeUsed {
			sign = append(sign, val)
			val.toBeUsed = true
		}
	}
	return sign
}

func ReadFile(name string) []byte {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		log.Println("Could not read file: %s\n", name)
		os.Exit(1)
	}
	return data
}
