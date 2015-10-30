package assembler

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

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
						// use s to sign certificate
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
		if val.signed && !val.toBeUsed && val.CertConfig.CA {
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
