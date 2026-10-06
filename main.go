package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/chrjoh/certificateBar/v2/certificatebar"
)

var (
	// -i and -d can be given both before and after renew, the flag sets share
	// the variables
	inputFile = "./config/data.yaml"
	input     string
	dir       string

	// renew sub command
	renewCmd    = flag.NewFlagSet("renew", flag.ExitOnError)
	renewSigner = renewCmd.String("p", "", "Id or commonname of the parent certificate whose certificates are renewed")
	renewDays   = renewCmd.Int("days", 0, "Make the renewed certificates valid from now and this many days, 0 uses the dates in the config file")
)

func init() {
	for _, fs := range []*flag.FlagSet{flag.CommandLine, renewCmd} {
		fs.StringVar(&input, "i", inputFile, "Config file defining the certificates")
		fs.StringVar(&dir, "d", ".", "Directory holding the certificate and key files")
		fs.Usage = usage
	}
}

// usage only prints, the caller decides the exit status: 0 for -h, 2 for a
// usage error.
func usage() {
	fmt.Fprintf(os.Stderr, "\nUsage:\n\n")
	fmt.Fprintf(os.Stderr, "  certificatebar [flags]                         create all certificates in the config file\n")
	fmt.Fprintf(os.Stderr, "  certificatebar [flags] renew -p <parent> ...   redo the certificates signed by <parent>\n")
	fmt.Fprintf(os.Stderr, "\nCommand line arguments:\n\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nrenew arguments:\n\n")
	renewCmd.PrintDefaults()
}

func usageError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	usage()
	os.Exit(2)
}

func main() {
	flag.Parse()

	switch {
	case flag.NArg() == 0:
		if err := certificatebar.Handler(input, dir); err != nil {
			log.Fatalf("Failed to generate: %v", err)
		}
	case flag.Arg(0) == "renew":
		renewCmd.Parse(flag.Args()[1:])
		if renewCmd.NArg() > 0 {
			usageError("unexpected arguments after renew: %v", renewCmd.Args())
		}
		if *renewSigner == "" {
			usageError("renew needs the parent certificate to renew from, given with -p")
		}
		if err := certificatebar.Renew(input, dir, *renewSigner, *renewDays); err != nil {
			log.Fatalf("Failed to renew: %v", err)
		}
	default:
		usageError("unknown command: %v", flag.Arg(0))
	}
}
