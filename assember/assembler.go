package assembler

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/chrjoh/certificateBar/certificate"
	"github.com/chrjoh/certificateBar/key"

	"gopkg.in/yaml.v2"
)

func Generate(filename string) Certs {
	c := Certs{}
	data := readFile(filename)
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	c.setupKeys()
	c.setupTemplates()
	c.setupSigner()
	c.signAll()
	return c
}

func (c *Certs) setupSigner() {
	c.certSigners = make(map[string][]string)
	for _, val := range c.Certificates {
		parent := val.CertConfig.Parent
		id := val.CertConfig.Id
		if parent == id {
			privKey := val.PrivateKey
			// self signed certificate
			val.CertBytes = certificate.Sign(val.CertTemplate, val.CertTemplate, key.PublicKey(privKey), privKey)
			val.signed = true
		} else if c.certSigners[parent] == nil {
			c.certSigners[parent] = []string{id}
		} else {
			c.certSigners[parent] = append(c.certSigners[parent], id)
		}
	}
}

func (c *Certs) setupKeys() {
	for _, cert := range c.Certificates {
		cert.PrivateKey = key.GenerateKey(cert.CertConfig.KeyType, cert.CertConfig.KeyLength)
	}
}

func (c *Certs) findByid(id string) (*Cert, error) {
	for _, cert := range c.Certificates {
		if cert.CertConfig.Id == id {
			return cert, nil
		}
	}
	return &Cert{}, errors.New("No cert found")
}

func (c *Certs) setupTemplates() {
	for _, cert := range c.Certificates {
		d := cert.CertConfig
		template := certificate.Certificate{
			Country:            d.Pkix.Country,
			Organization:       d.Pkix.Organization,
			OrganizationalUnit: d.Pkix.OrganizationUnit,
			CommonName:         d.Pkix.CommonName,
			AlternativeNames:   d.AltNames,
			CA:                 d.CA,
		}
		cert.CertTemplate = certificate.CreateCertificateTemplate(template)
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
			signer, _ := c.findByid(id)
			list := c.certSigners[id]
			for _, certId := range list {
				cert, _ := c.findByid(certId)
				cert.CertBytes = certificate.Sign(cert.CertTemplate, signer.CertTemplate, key.PublicKey(cert.PrivateKey), signer.PrivateKey)
				cert.signed = true
				if s.Signers == nil {
					cert.Signers = []string{id}
				} else {
					cert.Signers = append(s.Signers, id)
				}
			}
		}
	}
}

func (c Certs) Output() {
	for _, cert := range c.Certificates {
		if cert.signed {
			certificate.WritePemToFile(cert.CertBytes, cert.CertConfig.Id+"_crt.pem")
			key.WritePrivateKeyToPemFile(cert.PrivateKey, cert.CertConfig.Id+"_key.pem")
		}
		if len(cert.Signers) > 0 {
			fmt.Printf("Certificate: %s, has certificate chain: %v\n", cert.CertConfig.Id, strings.Join(cert.Signers, ", "))
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

func readFile(name string) []byte {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		log.Println("Could not read file: %s\n", name)
		os.Exit(1)
	}
	return data
}
