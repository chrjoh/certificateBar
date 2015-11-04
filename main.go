package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrjoh/certificateBar/certificatebar"
)

var (
	inputFile = "./config/data.yaml"
	// Command line flags
	inputFunc = flag.String("i", inputFile, "Config file defining the certificates")
)

func main() {
	// Command line usage information
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nCommand line arguments:\n\n")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Parse the command line flags
	flag.Parse()

	certificatebar.Handler(*inputFunc)
}
