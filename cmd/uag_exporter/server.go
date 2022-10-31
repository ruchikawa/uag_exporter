/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"log"

	"uag_exporter/pkg/server"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

// serverCmd represents the server command

// serverCmd represents the server command
func serverCmd() *cobra.Command {

	serverArgs := &server.Args{}

	serverCmd := &cobra.Command{
		Use:          "server",
		Short:        "Starts scaleio_exporter as a server",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return xerrors.Errorf("%q is an invalid argument", args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return server.Run(serverArgs)
		},
	}

	serverCmd.PersistentFlags().IntVarP(
		&serverArgs.Port,
		"port",
		"p",
		19443,
		"Exporter Listen Port",
	)

	serverCmd.PersistentFlags().IntVarP(
		&serverArgs.Refresh,
		"refresh",
		"r",
		300,
		"Refresh Interval Seconds",
	)

	serverCmd.PersistentFlags().StringVarP(
		&serverArgs.Username,
		"username",
		"u",
		"",
		"Username for UAG",
	)

	serverCmd.PersistentFlags().StringVarP(
		&serverArgs.Password,
		"password",
		"",
		"",
		"Password for UAG",
	)

	serverCmd.PersistentFlags().StringVarP(
		&serverArgs.IPAddr,
		"ipaddr",
		"i",
		"",
		"Specify UAG IPaddress",
	)

	serverCmd.PersistentFlags().BoolVarP(
		&serverArgs.Insecure,
		"insecure",
		"k",
		true,
		"Skip Verify Ceritificate(Insecure)",
	)

	if err := viper.BindPFlags(serverCmd.PersistentFlags()); err != nil {
		log.Fatalf("Failed to bind flags : %v\n", err)
	}

	cobra.OnInitialize(func() {
		viper.AutomaticEnv()
		if err := viper.Unmarshal(&serverArgs); err != nil {
			log.Fatalf("Failed to unmarshal arguments: %v\n", err)
		}
	})
	return serverCmd
}
