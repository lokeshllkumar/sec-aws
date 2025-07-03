package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/pinecone-io/go-pinecone/v4/pinecone"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
	"google.golang.org/protobuf/types/known/structpb"	
)

// defines the interface for Pinecone interactions
type PineconeClient interface {
	Query(ctx context.Context, embedding []float32, topK int) (*PineconeQueryResult, error)
	Upsert(ctx context.Context, vectors []PineconeVector) error
	Close() error
}

// represents the result of a Pinecone query
type PineconeQueryResult struct {
	Matches []PineconeMatch `json:"matches"`
}

// represents a single match in a Pinecone query result
type PineconeMatch struct {
	ID       string                 `json:"id"`
	Score    float32                `json:"score"`
	Metadata map[string]interface{} `json:"metadata"` // stored remediation details
}

// represents a single vector to be upserted into a Pinecone index
type PineconeVector struct {
	ID       string                 `json:"id"`
	Values   []float32              `json:"values"`
	Metadata map[string]interface{} `json:"metadata"`
}

// an implementation of the PineconeClient interface for actual API calls with Pinecone
type PineconeClientImpl struct {
	client    *pinecone.Client
	indexConn *pinecone.IndexConnection
}

// creates and returns a new Pinecone client
func NewPineconeClient(apiKey string, environment string, indexName string) (PineconeClient, error) {
	if apiKey == "" || environment == "" || indexName == "" {
		return nil, fmt.Errorf("pinecone API key, environment, or index name not configured")
	}

	// initializes Pinecone client
	pc, err := pinecone.NewClient(pinecone.NewClientParams{
		ApiKey: apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Pinecone client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	indexDesc, err := pc.DescribeIndex(ctx, indexName)
	if err != nil {
		return nil, fmt.Errorf("describe index error: %v", err)
	}

	indexConn, err := pc.Index(pinecone.NewIndexConnParams{
		Host: indexDesc.Host,
	})
	if err != nil {
		return nil, fmt.Errorf("index connection error: %w", err)
	}

	return &PineconeClientImpl{
		client:    pc,
		indexConn: indexConn,
	}, nil
}

func (p *PineconeClientImpl) Query(ctx context.Context, embedding []float32, topK int) (*PineconeQueryResult, error) {

	resp, err := p.indexConn.QueryByVectorValues(ctx, &pinecone.QueryByVectorValuesRequest{
		Vector:          embedding,
		TopK:            uint32(topK),
		IncludeMetadata: true,
	})
	if err != nil {
		return nil, fmt.Errorf("query failed: %v", err)
	}

	result := &PineconeQueryResult{
		Matches: make([]PineconeMatch, len(resp.Matches)),
	}
	for i, match := range resp.Matches {
		result.Matches[i] = PineconeMatch{
			ID:       match.Vector.Id,
			Score:    match.Score,
			Metadata: match.Vector.Metadata.AsMap(),
		}
	}
	logger.Log.Debugf("Query returned %d matches", len(result.Matches))
	return result, nil
}

// upserts vectors in the Pinecone index
func (p *PineconeClientImpl) Upsert(ctx context.Context, vectors []PineconeVector) error {
	logger.Log.Debugf("Upserting %d vectors to Pinecone index", len(vectors))

	pineconeVectors := make([]*pinecone.Vector, len(vectors))
	for i, vec := range vectors {
		metadataStruct, err := structpb.NewStruct(vec.Metadata)
		if err != nil {
			return fmt.Errorf("failed to convert metadata to struct: %v", err)
		}
		pineconeVectors[i] = &pinecone.Vector{
			Id:       vec.ID,
			Values:   &vec.Values,
			Metadata: metadataStruct,
		}
	}

	count, err := p.indexConn.UpsertVectors(ctx, pineconeVectors)
	if err != nil {
		return fmt.Errorf("upsert failed: %v", err)
	}
	logger.Log.Debugf("Successfully upserted %d vectors to Pinecone index", count)
	return nil
}

func (p *PineconeClientImpl) Close() error {
	logger.Log.Debug("Closing Pinecone client connection")
	return p.indexConn.Close()
}
