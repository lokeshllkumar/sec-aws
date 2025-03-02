package pinecone

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type EmbeddingRequest struct {
	Input string `json:"inp"`
}

type EmbeddingResponse struct {
	Embedding []float32 `json:"embedding"`
}

func GenerateEmbedding(issueStr string) ([]float32, error) {
	url := "http://0.0.0.0:8000/embedding"

	// forming request payload
	reqBody, _ := json.Marshal(EmbeddingRequest{
		Input: issueStr,
	})

	// creating HTTP request
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	// sending HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var respData EmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return respData.Embedding, nil
}
