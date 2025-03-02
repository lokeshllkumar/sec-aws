package main

import (
	"log"
	"os"

	"github.com/lokeshllkumar/sec-aws/internal/cmd"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sec-scan-aws",
		Short: "AI-powered AWS Security Scanner CLI",
	}

	rootCmd.AddCommand(cmd.AuditCmd)
	rootCmd.AddCommand(cmd.FixCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
