package certificatebar

import assembler "github.com/chrjoh/certificateBar/v2/assember"

// Handler creates every certificate in the config file.
func Handler(config, dir string) error {
	certs := assembler.Generate(config, dir)
	return certs.Output()
}

// Renew redoes the certificates signed by signerName, keeping that signer and
// everything above it as it is on disk.
func Renew(config, dir, signerName string, days int) error {
	certs, err := assembler.Renew(config, dir, signerName, days)
	if err != nil {
		return err
	}
	return certs.Output()
}
