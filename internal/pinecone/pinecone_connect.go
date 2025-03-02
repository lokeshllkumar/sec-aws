package pinecone

import (
	"context"
	"log"

	"github.com/lokeshllkumar/sec-aws/internal/utils"
	"github.com/pinecone-io/go-pinecone/v3/pinecone"
)

func PineconeConnect() (context.Context, *pinecone.Client) {
	ctx := context.Background()

	pc, err := pinecone.NewClient(pinecone.NewClientParams{
		ApiKey: utils.PineconeApiKey,
	})
	if err != nil {
		log.Fatalf("Failed to create Client: %v", err)
	}

	return ctx, pc
}
