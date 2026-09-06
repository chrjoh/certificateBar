package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/chrjoh/certificateBar/v2/certificatebar"
)

var (
	inputFile = "./config/data.yaml"
	// Command line flags
	inputFunc = flag.String("i", inputFile, "Config file defining the certificates")
	dirFunc   = flag.String("d", ".", "Directory to write the certificate and key files to")

	// renew sub command
	renewCmd    = flag.NewFlagSet("renew", flag.ExitOnError)
	renewInput  = renewCmd.String("i", inputFile, "Config file defining the certificates")
	renewDir    = renewCmd.String("d", ".", "Directory holding the certificate and key files")
	renewSigner = renewCmd.String("p", "", "Id or commonname of the parent certificate whose certificates are renewed")
	renewDays   = renewCmd.Int("days", 0, "Make the renewed certificates valid from now and this many days, 0 uses the dates in the config file")
)

func usage() {
	fmt.Fprintf(os.Stderr, "\nUsage:\n\n")
	fmt.Fprintf(os.Stderr, "  certificatebar [flags]                 create all certificates in the config file\n")
	fmt.Fprintf(os.Stderr, "  certificatebar renew -p <parent> ...   redo the certificates signed by <parent>\n")
	fmt.Fprintf(os.Stderr, "\nCommand line arguments:\n\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nrenew arguments:\n\n")
	renewCmd.PrintDefaults()
	os.Exit(0)
}

func main() {
	// Command line usage information
	flag.Usage = usage

	if len(os.Args) > 1 && os.Args[1] == "renew" {
		renewCmd.Usage = usage
		renewCmd.Parse(os.Args[2:])
		if *renewSigner == "" {
			fmt.Fprintf(os.Stderr, "renew needs the parent certificate to renew from, given with -p\n")
			usage()
		}
		if err := certificatebar.Renew(*renewInput, *renewDir, *renewSigner, *renewDays); err != nil {
			log.Fatalf("Failed to renew: %v", err)
		}
		return
	}

	// Parse the command line flags
	flag.Parse()

	certificatebar.Handler(*inputFunc, *dirFunc)
}
