package pinecone

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/lokeshllkumar/sec-aws/internal/utils"
	"github.com/pinecone-io/go-pinecone/v3/pinecone"
	"google.golang.org/protobuf/types/known/structpb"
)

func pbStructToStruct(pbStruct *structpb.Struct) (*utils.SecurityIssueMetadata, error) {
	if pbStruct == nil {
		return nil, fmt.Errorf("structpb.Struct is nil")
	}

	jsonBytes, err := json.Marshal(pbStruct.AsMap())
	if err != nil {
		return nil, err
	}

	var metadata utils.SecurityIssueMetadata
	if err := json.Unmarshal(jsonBytes, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// returns the metadata of the retrieved vector from the index
func QueryIssue(issue utils.SecurityIssue) (*utils.SecurityIssueMetadata, error) {
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

	// generating metadata filter
	metadataFilterMap := map[string]interface{}{
		"service": issue.Service,
	}
	metadataFilter, err := structpb.NewStruct(metadataFilterMap)
	if err != nil {
		log.Fatalf("Error parsing metadata filter for querying: %v", err)
	}

	// query the index for matches
	queryRes, err := idxConnection.QueryByVectorValues(ctx, &pinecone.QueryByVectorValuesRequest{
		Vector:          embedding,
		TopK:            1,
		MetadataFilter:  metadataFilter,
		IncludeMetadata: true,
		IncludeValues:   true,
	})
	if err != nil {
		log.Fatalf("Pinecone query failed: %v", err)
	}

	if len(queryRes.Matches) == 0 {
		return nil, fmt.Errorf("no vectors found in the index")
	}

	metadata, err := pbStructToStruct(queryRes.Matches[0].Vector.Metadata)
	if err != nil {
		log.Fatalf("Error parsing metadata: %v", err)
	}
	return metadata, nil
}
