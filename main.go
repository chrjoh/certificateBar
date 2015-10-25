package main

import (
	"github.com/chrjoh/certificateBar/certificate"
	"github.com/chrjoh/certificateBar/yaml"
)

func main() {
	certificate.Handler()
	yaml.Handler()

}
