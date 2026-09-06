package assembler

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chrjoh/certificateBar/v2/certificate"
)

// generateTree writes a complete certificate tree from the fixture into a
// temporary directory and returns the directory plus the bytes of every file.
func generateTree(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	certs := Generate("_fixtures/data.yaml", dir)
	certs.Output()
	return dir, snapshot(t, dir)
}

func snapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		t.Fatalf("could not list %v: %v", dir, err)
	}
	result := make(map[string][]byte)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("could not read %v: %v", file, err)
		}
		result[filepath.Base(file)] = data
	}
	return result
}

func decodePem(t *testing.T, data []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no pem data to decode")
	}
	return block.Bytes
}

// certifyChain verifies leaf against the given root and intermediates, all in pem form.
func certifyChain(t *testing.T, ca, leaf []byte, inters ...[]byte) bool {
	t.Helper()
	interDer := []byte{}
	for _, inter := range inters {
		interDer = append(interDer, decodePem(t, inter)...)
	}
	return certificate.CheckCertificate("", decodePem(t, ca), interDer, decodePem(t, leaf))
}

func TestRenewSignsWithTheCertificateOnDisk(t *testing.T) {
	dir, before := generateTree(t)

	certs, err := Renew("_fixtures/data.yaml", dir, "interca", 30)
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	certs.Output()
	after := snapshot(t, dir)

	// the signer and everything outside its subtree is untouched on disk
	for _, name := range []string{"interca_crt.pem", "interca_key.pem",
		"mainca_crt.pem", "mainca_key.pem", "interca2_crt.pem", "interca3_crt.pem",
		"client2_crt.pem", "client2_key.pem", "clientecdsa_crt.pem", "maincaecdsa_crt.pem"} {
		if !bytes.Equal(before[name], after[name]) {
			t.Fatalf("renew changed %v, it is outside the renewed subtree", name)
		}
	}
	// the renewed certificate got new material
	for _, name := range []string{"client_crt.pem", "client_key.pem"} {
		if bytes.Equal(before[name], after[name]) {
			t.Fatalf("renew did not write a new %v", name)
		}
	}
	// and it verifies against the chain that was already on disk
	ok := certifyChain(t, before["mainca_crt.pem"], after["client_crt.pem"], before["interca_crt.pem"])
	if !ok {
		t.Fatal("renewed client certificate does not verify against the existing mainca -> interca chain")
	}
}

func TestRenewUsesTheGivenValidity(t *testing.T) {
	dir, _ := generateTree(t)
	certs, err := Renew("_fixtures/data.yaml", dir, "interca", 30)
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	client, _ := certs.findByid("client")
	cert, err := x509.ParseCertificate(client.CertBytes)
	if err != nil {
		t.Fatalf("could not parse renewed certificate: %v", err)
	}
	want := time.Now().AddDate(0, 0, 30)
	if cert.NotAfter.Sub(want) > time.Minute || want.Sub(cert.NotAfter) > time.Minute {
		t.Fatalf("renewed certificate expires %v, wanted %v", cert.NotAfter, want)
	}
	if cert.NotBefore.After(time.Now()) {
		t.Fatalf("renewed certificate is not valid yet: %v", cert.NotBefore)
	}
}

func TestRenewWalksTheWholeSubtree(t *testing.T) {
	dir, before := generateTree(t)
	certs, err := Renew("_fixtures/data.yaml", dir, "mainca", 0)
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	certs.Output()
	after := snapshot(t, dir)

	for _, name := range []string{"interca_crt.pem", "interca2_crt.pem", "interca3_crt.pem",
		"client_crt.pem", "client2_crt.pem"} {
		if bytes.Equal(before[name], after[name]) {
			t.Fatalf("renew from mainca did not redo %v", name)
		}
	}
	for _, name := range []string{"mainca_crt.pem", "mainca_key.pem",
		"maincaecdsa_crt.pem", "clientecdsa_crt.pem"} {
		if !bytes.Equal(before[name], after[name]) {
			t.Fatalf("renew from mainca changed %v, which is not below it", name)
		}
	}
	// a certificate two levels down still verifies against the untouched root
	if !certifyChain(t, before["mainca_crt.pem"], after["client2_crt.pem"], after["interca2_crt.pem"], after["interca3_crt.pem"]) {
		t.Fatal("client2 does not verify against the untouched root after renew")
	}
}

func TestRenewByCommonName(t *testing.T) {
	dir, before := generateTree(t)
	certs, err := Renew("_fixtures/data.yaml", dir, "www.inter.se", 0)
	if err != nil {
		t.Fatalf("renew by commonname failed: %v", err)
	}
	if certs.renewFrom != "interca" {
		t.Fatalf("commonname www.inter.se resolved to %v, wanted interca", certs.renewFrom)
	}
	certs.Output()
	after := snapshot(t, dir)
	if bytes.Equal(before["client_crt.pem"], after["client_crt.pem"]) {
		t.Fatal("renew by commonname did not redo client")
	}
	// www.bar2.se is used by interca2 and interca3, that has to be an error
	if _, err := Renew("_fixtures/data.yaml", dir, "www.bar2.se", 0); err == nil {
		t.Fatal("wanted an error for the commonname www.bar2.se, used by two certificates")
	}
}

func TestRenewRefusesBadSigners(t *testing.T) {
	dir, _ := generateTree(t)
	cases := []struct {
		name   string
		config string
		signer string
	}{
		{"unknown id", "_fixtures/data.yaml", "nosuchca"},
		{"leaf certificate", "_fixtures/data.yaml", "client"},
		{"ca without children", "_fixtures/childless_ca.yaml", "lonelyca"},
	}
	for _, tc := range cases {
		if _, err := Renew(tc.config, dir, tc.signer, 0); err == nil {
			t.Fatalf("%v: renew from %v was accepted", tc.name, tc.signer)
		}
	}
}

func TestRenewRefusesAKeyThatIsNotTheSigners(t *testing.T) {
	dir, _ := generateTree(t)
	// put another certificates key next to intercas certificate
	other, err := os.ReadFile(filepath.Join(dir, "interca2_key.pem"))
	if err != nil {
		t.Fatalf("could not read key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "interca_key.pem"), other, 0600); err != nil {
		t.Fatalf("could not write key: %v", err)
	}
	if _, err := Renew("_fixtures/data.yaml", dir, "interca", 0); err == nil {
		t.Fatal("renew accepted a private key that does not belong to the certificate")
	}
}

func TestRenewNeedsTheCertificateOnDisk(t *testing.T) {
	dir := t.TempDir()
	if _, err := Renew("_fixtures/data.yaml", dir, "interca", 0); err == nil {
		t.Fatal("renew accepted a directory without any certificates")
	}
}
