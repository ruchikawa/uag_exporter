package cmd

import "github.com/spf13/cobra"

func GetRootCmd(args []string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "uag_exporter",
		Short:        "uag_exporter is a Prometheus Exporter that collects some metrics from Unified Access Gateway",
		SilenceUsage: true,
	}

	rootCmd.SetArgs(args)
	rootCmd.AddCommand(serverCmd())

	return rootCmd
}
