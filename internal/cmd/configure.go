package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lokeshllkumar/sec-aws/internal/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configureCmd = &cobra.Command{
	Use: "configure",
	Short: "Configure settings",
	Long: "Allows configuration of AWS credentials, LLM API keys, Pinecone settings, and other preferences.",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.Log.Info("Starting configuration...")

		// setting region
		fmt.Printf("Enter AWS region (current: %s):", viper.GetString("aws.region"))
		var region string
		fmt.Scanln(&region)
		if region != "" {
			viper.Set("aws.region", region)
			logger.Log.Debugf("Set AWS region to: %s", region)
		}

		// choosing LLM provider (Ollama or OpenAI)
		fmt.Printf("Choose LLM provider (ollama/openai, current: %s): ", viper.GetString("ai.llm_choice"))
		var llm string
		fmt.Scanln(&llm)
		llm = strings.ToLower(strings.TrimSpace(llm))
		if llm == "ollama" || llm == "openai" {
			viper.Set("ai.llm_choice", llm)
			logger.Log.Debugf("Set LLM choice to: %s", llm)
		} else if llm != "" {
			logger.Log.Warnf("Invalid LLM choice: '%s'. Retaining current setting", llm)
		}

		// Ollama URL (local/remote API)
		if viper.GetString("ai.llm_choice") == "ollama" {
			fmt.Printf("Enter Ollama API URL (current: %s): ", viper.GetString("ollama.api_url"))
			var ollamaURL string
			fmt.Scanln(&ollamaURL)
			if ollamaURL != "" {
				viper.Set("ollama.api_url", ollamaURL)
				logger.Log.Debugf("Set Ollama API URL to: %s", ollamaURL)
			}

			fmt.Printf("Enter Ollama model name (current: %s): ", viper.GetString("ollama.model_name"))
			var ollamaModelName string
			fmt.Scanln(&ollamaModelName)
			if ollamaModelName != "" {
				viper.Set("ollama.model_name", ollamaModelName)
				logger.Log.Debugf("Set Ollama model name to: %s", ollamaModelName)
			} else {
				logger.Log.Warn("Ollama model name cannot be empty. Retaining current setting.")
			}
		}

		// OpenAI API key
		if viper.GetString("ai.llm_choice") == "openai" {
			fmt.Printf("Enter OpenAI API key (current: %s): ", maskKey(viper.GetString("openai.api_key")))
			var openAIAPIKey string
			fmt.Scanln(&openAIAPIKey)
			if openAIAPIKey != "" {
				viper.Set("openai.api_key", openAIAPIKey)
				logger.Log.Debug("Set OpenAI API key")
			}
		}

		// Pinecone API key
		fmt.Printf("Enter Pinecone API key (current: %s): ", maskKey(viper.GetString("pinecone.api_key")))
		var pineconeAPIKey string
		fmt.Scanln(&pineconeAPIKey)
		if pineconeAPIKey != "" {
			viper.Set("pinecone.api_key", pineconeAPIKey)
			logger.Log.Debug("Set Pinecone API key")
		}

		// Pinecone env
		fmt.Printf("Enter Pinecone environment (current: %s): ", viper.GetString("pinecone.environment"))
		var pineconeEnv string
		fmt.Scanln(&pineconeEnv)
		if pineconeEnv != "" {
			viper.Set("pinecone.environment", pineconeEnv)
			logger.Log.Debugf("Set Pinecone environment to %s: ", pineconeEnv)
		}

		fmt.Printf("Enter Pinecone index name (current: %s): ", viper.GetString("pinecone.index"))
		var pineconeIndex string
		fmt.Scanln(&pineconeIndex)
		if pineconeIndex != "" {
			viper.Set("pinecone.index", pineconeIndex)
			logger.Log.Debugf("Set Pinecone index to %s: ", pineconeIndex)
		}

		// embedding server URL
		fmt.Printf("Enter embedding server URL (current: %s): ", viper.GetString("embedding_server.url"))
		var embeddingServerURL string
		fmt.Scanln(&embeddingServerURL)
		if embeddingServerURL != "" {
			viper.Set("embedding_server.url", embeddingServerURL)
			logger.Log.Debugf("Set embedding server URL to: %s", embeddingServerURL)
		}

		// save config
		configPath := viper.ConfigFileUsed()
		if configPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("error getting user's home directory: %v", err)
			}
			configDir := filepath.Join(home, ".sec-aws")
			if err := os.MkdirAll(configDir, 0755); err != nil {
				return fmt.Errorf("failed to create config directory: %w", err)
			}
			configPath = filepath.Join(configDir, "config.yaml")
		}

		if err := viper.WriteConfigAs(configPath); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}

		logger.Log.Infof("Configuration saved to: %s", configPath)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(configureCmd)
}

func maskKey(s string) string {
	if len(s) < 4 {
		return "*******"
	}
	return s[:2] + strings.Repeat("*", len(s) - 4) + s[len(s) - 2:]
}