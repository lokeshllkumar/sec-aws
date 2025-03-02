package utils

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

var (
	AwsAccessKey   string
	AwsSecretKey   string
	AwsRegion      string
	OpenaiApiKey   string
	PineconeApiKey string
	PineconeHost   string
)

func LoadKeysFromEnv() {
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	AwsAccessKey = os.Getenv("AWS_ACCESS_KEY")
	AwsSecretKey = os.Getenv("AWS_SECRET_KEY")
	AwsRegion = os.Getenv("AWS_REGION")
	OpenaiApiKey = os.Getenv("OPENAI_API_KEY")
	PineconeApiKey = os.Getenv("PINECONE_API_KEY")
	PineconeHost = os.Getenv("PINECONE_HOST")
}
