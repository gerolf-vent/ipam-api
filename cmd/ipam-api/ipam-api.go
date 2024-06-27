package main

import (
	"flag"
	"os"

	"go.uber.org/zap"
	i "github.com/gerolf-vent/ipam-api/v2/internal"
)

func main() {
	var err error

	// Parse cli flags
	argConfig := flag.String("config", "config.json", "Path to configuration file")
	argDevMode := flag.Bool("dev-mode", false, "Whether to run in dev mode")
	flag.Parse()

	// Initialize logger
	if *argDevMode {
		zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
	} else {
		zap.ReplaceGlobals(zap.Must(zap.NewProduction()))
	}
	defer zap.L().Sync()

	// Run the server
	err = i.RunServer(*argConfig)
	if err != nil {
		zap.L().Error("Server terminated with error",
			zap.Error(err),
		)
		os.Exit(1)
	}

	zap.L().Info("Server has stopped gracefully")
}
