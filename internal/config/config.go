package config

import (
	"github.com/spf13/viper"
)

// setting up default values for Viper
func InitDefaultConfig() {
	viper.SetDefault("aws.region", "ap-south-1")
	viper.SetDefault("ai.llm_choice", "ollama")
	viper.SetDefault("ollama.api_url", "http://localhost:11434")
	viper.SetDefault("openai.api_key", "")
	viper.SetDefault("ollama.model_name", "granite3.1-moe")
	viper.SetDefault("pinecone.api_key", "")
	viper.SetDefault("pinecone.environment", "")
	viper.SetDefault("pinecone.index", "")
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("embedding_server.url", "http://localhost:8000/embed") // Py embedding server's URL
}