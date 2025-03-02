package pinecone

import (
	"fmt"
	"log"
	"time"

	"github.com/lokeshllkumar/sec-aws/internal/utils"
	"github.com/pinecone-io/go-pinecone/v3/pinecone"
	"google.golang.org/protobuf/types/known/structpb"
)

func generateIssueID(service string) string {
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	return fmt.Sprintf("%s-%s", service, timestamp)
}

func generateIssueMetadata(issue utils.SecurityIssue, securityFix string) (*structpb.Struct, error) {
	issueMap := map[string]interface{}{
		"service": issue.Service,
		"resource_name": issue.ResourceName,
		"details": issue.Details,
		"severity": issue.Severity,
		"fix": securityFix,
	}

	// converting map to structpb.Struct
	structPB, err := structpb.NewStruct(issueMap)
	if err != nil {
		return nil, err
	}
	
	return structPB, nil
}

func UpsertIssue(issue utils.SecurityIssue, securityFix string) {
	issueStr := issue.StringifyIssue()
	embedding, err := GenerateEmbedding(issueStr)
	if err != nil {
		log.Fatalf("Error generating embedding: %v", embedding)
	}

	ctx, pc := PineconeConnect()
	idxConnection, err := pc.Index(pinecone.NewIndexConnParams{
		Host: utils.PineconeHost,
	})
	if err != nil {
		log.Fatalf("Failed to create IndexConnection for Host: %v", err)
	}

	// no need to use sparse values to populate index with vectors; embeddings generated are dense
	vectorID := generateIssueID(issue.Service)
	vectorMetadata, err := generateIssueMetadata(issue, securityFix)
	if err != nil {
		log.Fatalf("Error parsing security issue's metadata: %v", err)
	}

	vector := []*pinecone.Vector{
		{
			Id: vectorID,
			Values: &embedding,
			Metadata: vectorMetadata,
		},
	}

	count, err := idxConnection.UpsertVectors(ctx, vector)
	if err != nil {
		log.Fatalf("Failed to upsert vectors to index: %v", err)
	} else {
		fmt.Printf("Succefully upserted %d vector(s)\n", count)
	}
}
