package yaml

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"

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
	PrivateKey   rsa.PrivateKey
	CertTemplate x509.Certificate
	CertBytes    []byte
}

type Certs struct {
	Certificates []Cert `yaml:"certificates"`
}

func Handler() {
	test := Certs{}
	data := ReadFile("./config/data.yaml")
	err := yaml.Unmarshal(data, &test)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	fmt.Printf("--- test:\n%v\n\n", test)
	fmt.Printf("country: %s\n", test.Certificates[2].CertConfig.AltNames)

}

func ReadFile(name string) []byte {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		log.Println("Could not read file: %s\n", name)
		os.Exit(1)
	}
	return data
}
