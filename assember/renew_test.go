package assembler

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/chrjoh/certificateBar/v2/certificate"
)

var (
	treeOnce sync.Once
	tree     map[string][]byte
)

// generateTree gives every test its own copy of one complete certificate tree
// from the fixture, generated once for the whole test run, and returns the
// directory plus the bytes of every file.
func generateTree(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	treeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "renew_test")
		if err != nil {
			t.Fatalf("could not create directory: %v", err)
		}
		defer os.RemoveAll(dir)
		certs := Generate("_fixtures/data.yaml", dir)
		if err := certs.Output(); err != nil {
			t.Fatalf("could not write the tree: %v", err)
		}
		tree = snapshot(t, dir)
	})
	if tree == nil {
		t.Fatal("no certificate tree to start from")
	}
	dir := t.TempDir()
	for name, data := range tree {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatalf("could not write %v: %v", name, err)
		}
	}
	return dir, tree
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

func parsePem(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(decodePem(t, data))
	if err != nil {
		t.Fatalf("could not parse certificate: %v", err)
	}
	return cert
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

func renew(t *testing.T, config, dir, signer string, days int) Certs {
	t.Helper()
	certs, err := Renew(config, dir, signer, days)
	if err != nil {
		t.Fatalf("renew from %v failed: %v", signer, err)
	}
	if err := certs.Output(); err != nil {
		t.Fatalf("could not write the renewed certificates: %v", err)
	}
	return certs
}

// writeInterca replaces interca on disk with a self signed ca made from priv,
// valid notBefore .. notAfter.
func writeInterca(t *testing.T, dir string, priv crypto.Signer, notBefore, notAfter time.Time) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "www.inter.se"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("could not create interca: %v", err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("could not marshal interca key: %v", err)
	}
	files := map[string][]byte{
		"interca_crt.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"interca_key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatalf("could not write %v: %v", name, err)
		}
	}
}

func TestRenewSignsWithTheCertificateOnDisk(t *testing.T) {
	dir, before := generateTree(t)
	certs := renew(t, "_fixtures/data.yaml", dir, "interca", 30)
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
	// the reported chain is the full one, as Generate reports it
	client, _ := certs.findByid("client")
	if want := []string{"mainca", "interca"}; !reflect.DeepEqual(client.Signers, want) {
		t.Fatalf("renewed client has chain %v, wanted %v", client.Signers, want)
	}
	// only the renewed subtree is part of the result
	if len(certs.Certificates) != 2 {
		t.Fatalf("renew from interca handled %d certificates, wanted interca and client", len(certs.Certificates))
	}
}

func TestRenewGivesANewSerialNumber(t *testing.T) {
	dir, before := generateTree(t)
	renew(t, "_fixtures/data.yaml", dir, "interca", 0)
	after := snapshot(t, dir)
	old, renewed := parsePem(t, before["client_crt.pem"]), parsePem(t, after["client_crt.pem"])
	if !bytes.Equal(old.RawIssuer, renewed.RawIssuer) {
		t.Fatal("renewed client has another issuer than before")
	}
	if old.SerialNumber.Cmp(renewed.SerialNumber) == 0 {
		t.Fatalf("renewed client reuses serial %v of the certificate it replaces", old.SerialNumber)
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
	renew(t, "_fixtures/data.yaml", dir, "mainca", 0)
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
	certs := renew(t, "_fixtures/data.yaml", dir, "www.inter.se", 0)
	if !certs.Certificates[0].pinned || certs.Certificates[0].CertConfig.Id != "interca" {
		t.Fatalf("commonname www.inter.se did not resolve to interca")
	}
	after := snapshot(t, dir)
	if bytes.Equal(before["client_crt.pem"], after["client_crt.pem"]) {
		t.Fatal("renew by commonname did not redo client")
	}
	// www.bar2.se is used by interca2 and interca3, that has to be an error
	if _, err := Renew("_fixtures/data.yaml", dir, "www.bar2.se", 0); err == nil {
		t.Fatal("wanted an error for the commonname www.bar2.se, used by two certificates")
	}
}

func TestRenewOnlyLooksAtItsSubtree(t *testing.T) {
	dir, _ := generateTree(t)
	// broken, outside the subtree, has a keytype that would stop a Generate
	certs, err := Renew("_fixtures/renew_extra.yaml", dir, "interca", 0)
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if _, err := certs.findByid("broken"); err == nil {
		t.Fatal("renew from interca kept broken, which is not below it")
	}
	// grandchild is below interca but its parent is no ca, it has to stay
	// in the result as not signed so that Output reports it
	grandchild, err := certs.findByid("grandchild")
	if err != nil {
		t.Fatal("renew from interca dropped grandchild, which is below it")
	}
	if grandchild.signed {
		t.Fatal("grandchild was signed by a certificate that is no ca")
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

func TestRenewRefusesAKeyThatCanNotSign(t *testing.T) {
	dir, _ := generateTree(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}
	writeInterca(t, dir, priv, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0))
	if _, err := Renew("_fixtures/data.yaml", dir, "interca", 0); err == nil {
		t.Fatal("renew accepted an ed25519 signer")
	}
}

func TestRenewSignsWithAnotherKeyFamily(t *testing.T) {
	dir, _ := generateTree(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}
	// an ECDSA interca signing the RSA client
	writeInterca(t, dir, priv, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0))
	renew(t, "_fixtures/data.yaml", dir, "interca", 0)
	after := snapshot(t, dir)
	if !certifyChain(t, after["interca_crt.pem"], after["client_crt.pem"]) {
		t.Fatal("RSA client does not verify against its ECDSA signer")
	}
}

func TestRenewRefusesASignerOutsideItsValidity(t *testing.T) {
	cases := []struct {
		name                string
		notBefore, notAfter time.Time
	}{
		{"expired", time.Now().AddDate(-2, 0, 0), time.Now().AddDate(-1, 0, 0)},
		{"not yet valid", time.Now().AddDate(0, 0, 1), time.Now().AddDate(1, 0, 0)},
	}
	for _, tc := range cases {
		dir, _ := generateTree(t)
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		writeInterca(t, dir, priv, tc.notBefore, tc.notAfter)
		if _, err := Renew("_fixtures/data.yaml", dir, "interca", 0); err == nil {
			t.Fatalf("%v: renew accepted the signer", tc.name)
		}
	}
}

func TestRenewDoesNotOutliveTheSigner(t *testing.T) {
	dir, _ := generateTree(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	end := time.Now().AddDate(0, 0, 10).Truncate(time.Second)
	writeInterca(t, dir, priv, time.Now().Add(-time.Hour), end)
	renew(t, "_fixtures/data.yaml", dir, "interca", 30)
	client := parsePem(t, snapshot(t, dir)["client_crt.pem"])
	if !client.NotAfter.Equal(end) {
		t.Fatalf("client expires %v, wanted the end of interca %v", client.NotAfter, end)
	}
}

func TestOutputLeavesThePairAloneWhenItCanNotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read only directory")
	}
	dir, before := generateTree(t)
	certs, err := Renew("_fixtures/data.yaml", dir, "interca", 0)
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("could not make %v read only: %v", dir, err)
	}
	defer os.Chmod(dir, 0700)
	if err := certs.Output(); err == nil {
		t.Fatal("Output reported success writing to a read only directory")
	}
	after := snapshot(t, dir)
	for _, name := range []string{"client_crt.pem", "client_key.pem"} {
		if !bytes.Equal(before[name], after[name]) {
			t.Fatalf("a failed Output changed %v", name)
		}
	}
	if len(after) != len(before) {
		t.Fatalf("a failed Output left %d files behind, wanted %d", len(after), len(before))
	}
}

func TestOutputWritesKeysPrivate(t *testing.T) {
	dir, _ := generateTree(t)
	renew(t, "_fixtures/data.yaml", dir, "interca", 0)
	info, err := os.Stat(filepath.Join(dir, "client_key.pem"))
	if err != nil {
		t.Fatalf("could not stat key: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("client_key.pem has mode %v, wanted 0600", info.Mode().Perm())
	}
}

func TestRenewNeedsTheCertificateOnDisk(t *testing.T) {
	dir := t.TempDir()
	if _, err := Renew("_fixtures/data.yaml", dir, "interca", 0); err == nil {
		t.Fatal("renew accepted a directory without any certificates")
	}
}
