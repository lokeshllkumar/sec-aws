package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"path/filepath"

	"github.com/lokeshllkumar/sec-aws/internal/logger"
	"github.com/lokeshllkumar/sec-aws/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configFile string
var logLevel string
var awsRegion string
var llmChoice string // either "ollama" for "openai"
var verbose bool

// base command
var rootCmd = &cobra.Command{
	Use: "sec-aws",
	Short: "An AWS security scanner with AI-powered remediation",
	Long: `sec-aws is a CLI tool designed to identify common vulnerabilties in AWS services (namely EC2, IAM, and S3) and provide AI-powered remediation suggestions.
	Supporting a RAG for remediation by storing vulnerability-remediation pairs in Pinecone and leveraging either a local Ollama instance or the OpenAI API for reasoning.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		logger.Init(logLevel, os.Stdout)

		if configFile != "" {
			viper.SetConfigFile(configFile)
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				logger.Log.Fatalf("Error getting user's home directory: %v", err)
			}
			viper.AddConfigPath(filepath.Join(home, ".sec-aws"))
			viper.AddConfigPath(".")
			viper.SetConfigName("config")
		}

		viper.AutomaticEnv()
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

		if err := viper.ReadInConfig(); err == nil {
			logger.Log.Debugf("Using config file: %s", viper.ConfigFileUsed())
		} else {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				logger.Log.Warn("No config file found, using defaults and environment variables")
			} else {
				logger.Log.Fatalf("Error reading config file: %v", err)
			}
		}

		// binding flags to Viper
		viper.BindPFlag("aws.region", cmd.PersistentFlags().Lookup("region"))
		viper.BindPFlag("ai.llm_choice", cmd.PersistentFlags().Lookup("llm"))
		viper.BindPFlag("logging.level", cmd.PersistentFlags().Lookup("log-level"))
		viper.BindPFlag("verbose", cmd.PersistentFlags().Lookup("verbose"))

		if verbose {
			logger.SetLevel("debug")
		}

		return nil
	},
}

// executes all child commands to the root commands and sets flags appropriately
func Execute() {
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(config.InitDefaultConfig)

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is ~/.sec-aws/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&awsRegion, "region", "us-east-1", "Choose AWS region to scan")
	rootCmd.PersistentFlags().StringVar(&llmChoice, "llm", "ollama", "Choose LLM provider: ollama or openai")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Set logging level (debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging (sets the log-level to debug by default)")
}