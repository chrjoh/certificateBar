package assembler

import (
	"crypto"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chrjoh/certificateBar/v2/certificate"
	"github.com/chrjoh/certificateBar/v2/key"

	"gopkg.in/yaml.v2"
)

// Generate creates every certificate in the config file from scratch, writing
// the result to dir.
func Generate(filename, dir string) Certs {
	c := parse(filename, dir)
	c.setupKeys()
	c.setupTemplates()
	c.setupSigner()
	c.signAll()
	return c
}

// Renew redoes everything below signerName in the tree described by the config
// file, reusing the certificate and private key already on disk for signerName.
// The chain above it, and every certificate outside its subtree, is left alone.
// days > 0 gives the renewed certificates a validity of now .. now + days
// instead of the dates in the config file.
func Renew(filename, dir, signerName string, days int) (Certs, error) {
	c := parse(filename, dir)
	c.renewDays = days
	signer, err := c.findSigner(signerName)
	if err != nil {
		return c, err
	}
	c.renewFrom = signer.CertConfig.Id
	if err := c.pin(signer); err != nil {
		return c, err
	}
	c.setupKeys()
	c.setupTemplates()
	c.setupSigner()
	c.signAll()
	return c, nil
}

func parse(filename, dir string) Certs {
	c := Certs{dir: dir}
	data := readFile(filename)
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	return c
}

// pin loads the certificate and key already on disk for cert and marks it as a
// finished signer, so that a renew signs with the exact same issuer the
// existing chain was built with.
func (c *Certs) pin(cert *Cert) error {
	id := cert.CertConfig.Id
	privateKey, err := key.ReadPrivateKeyFromPemFile(c.path(keyFileName(id)))
	if err != nil {
		return err
	}
	template, err := certificate.ReadPemFromFile(c.path(certFileName(id)))
	if err != nil {
		return err
	}
	signer, isSigner := privateKey.(crypto.Signer)
	pub, comparable := template.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !isSigner || !comparable || !pub.Equal(signer.Public()) {
		return fmt.Errorf("private key %s does not belong to certificate %s",
			c.path(keyFileName(id)), c.path(certFileName(id)))
	}
	cert.PrivateKey = privateKey
	cert.CertTemplate = template
	cert.CertBytes = template.Raw
	cert.signed = true
	cert.pinned = true
	return nil
}

func (c *Certs) path(name string) string {
	return filepath.Join(c.dir, name)
}

func (c *Certs) setupSigner() {
	c.certSigners = make(map[string][]string)
	for _, val := range c.Certificates {
		parent := val.CertConfig.Parent
		id := val.CertConfig.Id
		switch {
		case c.renewFrom != "":
			// Renewing: the tree is only walked downwards from the pinned
			// certificate, so no root is self signed here.
			if id != c.renewFrom && parent != id {
				c.certSigners[parent] = append(c.certSigners[parent], id)
			}
		case parent == id:
			privKey := val.PrivateKey
			// self signed certificate
			val.CertBytes = certificate.Sign(val.CertTemplate, val.CertTemplate, key.PublicKey(privKey), privKey)
			val.signed = true
		default:
			c.certSigners[parent] = append(c.certSigners[parent], id)
		}
	}
}

func (c *Certs) setupKeys() {
	for _, cert := range c.Certificates {
		if cert.pinned {
			continue
		}
		rsaBitsLenght := 2048
		if cert.CertConfig.KeyLength > 0 {
			rsaBitsLenght = cert.CertConfig.KeyLength
		}
		cert.PrivateKey = key.GenerateKey(cert.CertConfig.KeyType, rsaBitsLenght)
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

// findSigner looks up the certificate to renew from, by id or by common name,
// and refuses one that can not sign anything.
func (c *Certs) findSigner(name string) (*Cert, error) {
	found := []*Cert{}
	for _, cert := range c.Certificates {
		if cert.CertConfig.Id == name || cert.CertConfig.Pkix.CommonName == name {
			found = append(found, cert)
		}
	}
	switch {
	case len(found) == 0:
		return &Cert{}, fmt.Errorf("no certificate with id or commonname: %v", name)
	case len(found) > 1:
		return &Cert{}, fmt.Errorf("commonname %v is used by %d certificates, use the id instead", name, len(found))
	case !found[0].CertConfig.CA:
		return &Cert{}, fmt.Errorf("certificate %v is not a ca and can not sign anything", found[0].CertConfig.Id)
	case len(c.children(found[0].CertConfig.Id)) == 0:
		return &Cert{}, fmt.Errorf("certificate %v has no certificates to renew", found[0].CertConfig.Id)
	}
	return found[0], nil
}

func (c *Certs) children(id string) []string {
	children := []string{}
	for _, cert := range c.Certificates {
		if cert.CertConfig.Parent == id && cert.CertConfig.Id != id {
			children = append(children, cert.CertConfig.Id)
		}
	}
	return children
}

func (c *Certs) setupTemplates() {
	for _, cert := range c.Certificates {
		if cert.pinned {
			// template comes from the certificate on disk
			continue
		}
		d := cert.CertConfig
		validFrom, validTo := d.ValidFrom(), d.ValidTo()
		if c.renewDays > 0 {
			validFrom = time.Now()
			validTo = validFrom.AddDate(0, 0, c.renewDays)
		}
		template := certificate.Certificate{
			Id:                 d.Id,
			Country:            d.Pkix.Country,
			Organization:       d.Pkix.Organization,
			OrganizationalUnit: d.Pkix.OrganizationUnit,
			CommonName:         d.Pkix.CommonName,
			AlternativeNames:   d.AltNames,
			CA:                 d.CA,
			PrivateKey:         cert.PrivateKey,
			SignatureAlg:       d.HashAlg,
			ValidFrom:          validFrom,
			ValidTo:            validTo,
			Usage:              d.Usage,
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
		id := cert.CertConfig.Id
		if cert.pinned {
			fmt.Printf("Certificate: %s, reused as signer, left untouched on disk\n", id)
			continue
		}
		if c.renewFrom != "" && !cert.signed {
			// outside the renewed subtree, not our business
			continue
		}
		if cert.signed {
			certificate.WritePemToFile(cert.CertBytes, c.path(certFileName(id)))
			key.WritePrivateKeyToPemFile(cert.PrivateKey, c.path(keyFileName(id)))
		}
		if len(cert.Signers) > 0 {
			fmt.Printf("Certificate: %s, has certificate chain: %v\n", id, strings.Join(cert.Signers, ", "))
		}
		if !cert.signed {
			fmt.Printf("Failed to sign: %s\n", id)
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
	data, err := os.ReadFile(name)
	if err != nil {
		log.Printf("Could not read file: %s\n", name)
		os.Exit(1)
	}
	return data
}
