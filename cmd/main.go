package main

import (
	"log"
	"os"
	cmd "uag_exporter/cmd/uag_exporter"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	rootCmd := cmd.GetRootCmd(os.Args[1:])

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
