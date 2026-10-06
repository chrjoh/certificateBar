package assembler

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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
	if err := c.pin(signer); err != nil {
		return c, err
	}
	// From here on only the signer and the certificates below it exist, the
	// rest of the config is neither generated nor written.
	c.Certificates = c.subtree(signer.CertConfig.Id)
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
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		return fmt.Errorf("private key %s is a %T, only RSA and ECDSA keys can sign",
			c.path(keyFileName(id)), privateKey)
	}
	signer := privateKey.(crypto.Signer)
	pub, comparable := template.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !comparable || !pub.Equal(signer.Public()) {
		return fmt.Errorf("private key %s does not belong to certificate %s",
			c.path(keyFileName(id)), c.path(certFileName(id)))
	}
	now := time.Now()
	if now.Before(template.NotBefore) || now.After(template.NotAfter) {
		return fmt.Errorf("certificate %s is only valid %v .. %v, it can not sign now",
			c.path(certFileName(id)), template.NotBefore, template.NotAfter)
	}
	cert.PrivateKey = privateKey
	cert.CertTemplate = template
	cert.CertBytes = template.Raw
	cert.Signers = c.chainAbove(cert)
	cert.signed = true
	cert.pinned = true
	return nil
}

// chainAbove lists the ids from the root down to the parent of cert, as given
// by the config, the same chain Generate reports for it.
func (c *Certs) chainAbove(cert *Cert) []string {
	chain := []string{}
	seen := map[string]bool{cert.CertConfig.Id: true}
	for parent := cert.CertConfig.Parent; !seen[parent]; {
		p, err := c.findByid(parent)
		if err != nil {
			break
		}
		chain = append([]string{parent}, chain...)
		seen[parent] = true
		parent = p.CertConfig.Parent
	}
	return chain
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
		case val.pinned:
			// already signed, by a parent that is not part of this run
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
	case len(c.subtree(found[0].CertConfig.Id)) == 1:
		return &Cert{}, fmt.Errorf("certificate %v has no certificates to renew", found[0].CertConfig.Id)
	}
	return found[0], nil
}

// subtree returns the certificate with id followed by every certificate below
// it in the config, in config order.
func (c *Certs) subtree(id string) []*Cert {
	in := map[string]bool{id: true}
	for grown := true; grown; {
		grown = false
		for _, cert := range c.Certificates {
			d := cert.CertConfig
			if !in[d.Id] && in[d.Parent] {
				in[d.Id] = true
				grown = true
			}
		}
	}
	result := []*Cert{}
	for _, cert := range c.Certificates {
		if in[cert.CertConfig.Id] {
			result = append(result, cert)
		}
	}
	return result
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
				// The signature is made by the signer's key, so its family
				// decides the algorithm, the child's config only the hash.
				cert.CertTemplate.SignatureAlgorithm = certificate.SignatureAlgorithm(cert.CertConfig.HashAlg, signer.PrivateKey)
				if cert.CertTemplate.NotAfter.After(signer.CertTemplate.NotAfter) {
					fmt.Printf("Certificate: %s, validity cut to %v, the end of its signer %s\n",
						certId, signer.CertTemplate.NotAfter, id)
					cert.CertTemplate.NotAfter = signer.CertTemplate.NotAfter
				}
				cert.CertBytes = certificate.Sign(cert.CertTemplate, signer.CertTemplate, key.PublicKey(cert.PrivateKey), signer.PrivateKey)
				cert.signed = true
				cert.Signers = append(append([]string{}, s.Signers...), id)
			}
		}
	}
}

// Output writes every signed certificate and its key to disk and reports the
// certificates that could not be signed.
func (c Certs) Output() error {
	for _, cert := range c.Certificates {
		id := cert.CertConfig.Id
		if cert.pinned {
			fmt.Printf("Certificate: %s, reused as signer, left untouched on disk\n", id)
			continue
		}
		if cert.signed {
			if err := c.write(cert); err != nil {
				return err
			}
		}
		if len(cert.Signers) > 0 {
			fmt.Printf("Certificate: %s, has certificate chain: %v\n", id, strings.Join(cert.Signers, ", "))
		}
		if !cert.signed {
			fmt.Printf("Failed to sign: %s\n", id)
		}
	}
	return nil
}

// write puts the key and certificate of cert on disk as a pair: both are
// written to temporary files first, and only when both are complete do they
// replace the old files.
func (c Certs) write(cert *Cert) error {
	id := cert.CertConfig.Id
	keyPem, err := key.EncodePrivateKeyPem(cert.PrivateKey)
	if err != nil {
		return err
	}
	keyTmp, err := c.writeTemp(keyFileName(id), keyPem, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(keyTmp)
	certTmp, err := c.writeTemp(certFileName(id), certificate.EncodePem(cert.CertBytes), 0644)
	if err != nil {
		return err
	}
	defer os.Remove(certTmp)
	if err := os.Rename(keyTmp, c.path(keyFileName(id))); err != nil {
		return err
	}
	if err := os.Rename(certTmp, c.path(certFileName(id))); err != nil {
		return err
	}
	fmt.Printf("wrote certificate %s and key %s to file\n", c.path(certFileName(id)), c.path(keyFileName(id)))
	return nil
}

func (c Certs) writeTemp(name string, data []byte, perm os.FileMode) (string, error) {
	f, err := os.CreateTemp(c.dir, "."+name+".*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("could not write %s: %v", c.path(name), err)
	}
	return tmp, nil
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
