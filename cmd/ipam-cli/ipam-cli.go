package main

import (
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"
	i "github.com/gerolf-vent/ipam-api/v2/internal"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <operation> <interface_name> <address>\n\nOperations:\n    add      Add the address to the interface\n    delete   Delete the address from the interface\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Parse cli flags
	optDevMode := flag.Bool("dev-mode", false, "Whether to run in dev mode")
	flag.Parse()

	// Initialize logger
	if *optDevMode {
		zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
	} else {
		zap.ReplaceGlobals(zap.Must(zap.NewProduction()))
	}
	defer zap.L().Sync()

	argOperation := flag.Arg(0)
	if argOperation == "" {
		fmt.Fprintf(os.Stderr, "An operation is required (see -h for help)\n")
		os.Exit(1)
	}

	if argOperation != "add" && argOperation != "delete" {
		fmt.Fprintf(os.Stderr, "Invalid operation (see -h for help)\n")
		os.Exit(1)
	}

	argInterfaceName := flag.Arg(1)
	if argInterfaceName == "" {
		fmt.Fprintf(os.Stderr, "An interface name is required (see -h for help)\n")
		os.Exit(1)
	}

	link, err := i.LinkByName(argInterfaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get interface: %v\n", err)
		os.Exit(1)
	}

	argAddress := flag.Arg(2)
	if argAddress == "" {
		fmt.Fprintf(os.Stderr, "An address is required (see -h for help)\n")
		os.Exit(1)
	}

	address, err := i.ParseAddress(argAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse address: %v\n", err)
		os.Exit(1)
	}

	switch argOperation {
	case "add":
		if err := i.AddAddress(link, address); err != nil {
			// The error was already logged in the function
			os.Exit(1)
		}
	case "delete":
		if err := i.DeleteAddress(link, address); err != nil {
			// The error was already logged in the function
			os.Exit(1)
		}
	}
}
