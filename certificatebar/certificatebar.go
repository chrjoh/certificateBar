package certificatebar

import "github.com/chrjoh/certificateBar/assember"

func Handler(config string) {
	certs := assembler.Generate(config)
	certs.Output()
}
