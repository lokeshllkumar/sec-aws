package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/spf13/viper"
)

// defines a client for scanning
type Client struct {
	OllamaAPIURL        string
	OllamaModelName string
	OpenAIAPIKey        string
	EmbeddingServerURL  string
	PineconeAPIKey      string
	PineconeEnvironment string
	PineconeIndex       string
	LLMChoice           string
}

// initialized a new client with configurations
func NewClient() *Client {
	return &Client{
		OllamaAPIURL:        viper.GetString("ollama.api_url"),
		OllamaModelName: viper.GetString("ollama.model_name"),
		OpenAIAPIKey:        viper.GetString("openai.api_key"),
		EmbeddingServerURL:  viper.GetString("embedding_server.url"),
		PineconeAPIKey:      viper.GetString("pinecone.api_key"),
		PineconeEnvironment: viper.GetString("pinecone.environment"),
		PineconeIndex:       viper.GetString("pinecone.index"),
		LLMChoice:           viper.GetString("ai.llm_choice"),
	}
}

// retrieves a response from the configured LLM
func (c *Client) GetLLMResponse(ctx context.Context, prompt string) (string, error) {
	switch c.LLMChoice {
	case "ollama":
		return c.getOllamaResponse(ctx, prompt)
	case "openai":
		return c.getOpenAIResponse(ctx, prompt)
	default:
		return "", fmt.Errorf("unsupported LLM choice: %s", c.LLMChoice)
	}
}

// sends a request to the Ollama API
func (c *Client) getOllamaResponse(ctx context.Context, prompt string) (string, error) {
	if c.OllamaAPIURL == "" {
		return "", fmt.Errorf("ollama API URL not configured")
	}
	if c.OllamaModelName == "" {
		return "", fmt.Errorf("ollama model name not configured")
	}

	requestBody, _ := json.Marshal(map[string]interface{}{
		"model":  c.OllamaModelName,
		"prompt": prompt,
		"stream": false,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/generate", c.OllamaAPIURL), bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to Ollama create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 120 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send Ollama request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama returned a non-200 status code: %v, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode Ollama response: %v", err)
	}

	return response.Response, nil
}

// sends a request to the OpenAI API
func (c *Client) getOpenAIResponse(ctx context.Context, prompt string) (string, error) {
	if c.OpenAIAPIKey == "" {
		return "", fmt.Errorf("OpenAI API key not configured")
	}

	requestBody, _ := json.Marshal(map[string]interface{}{
		"model":  "gpt-3.5-turbo",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create OpenAI request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.OpenAIAPIKey))

	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send OpenAI request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("OpenAI returned a non-200 status code: %v, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode OpenAI response: %v", err)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no choices returned from OpenAI")
	}

	return response.Choices[0].Message.Content, nil
}

// sends a request to a local Python embedding server
func (c *Client) GetEmbeddings(ctx context.Context, text string) ([]float32, error) {
	if c.EmbeddingServerURL == "" {
		return nil, fmt.Errorf("embedding server URL not configured")
	}

	requestBody, _ := json.Marshal(map[string]string{
		"text": text,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", c.EmbeddingServerURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send embedding request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("embedding server returned a non-200 status code: %v, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		Embeddings []float32 `json:"embeddings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode embedding response: %v", err)
	}

	if len(response.Embeddings) == 0 {
		return nil, fmt.Errorf("embedding server returned empty embedding")
	}

	return response.Embeddings, nil
}

// holds extracted code and steps
type RemediationDetails struct {
	Code string
	Steps []string
}

func GetRemediation(llmResponse string) (*RemediationDetails, error) {
	code, err := parseCode(llmResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remediation code: %w", err)
	}

	steps, err := parseSteps(llmResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remediation steps: %w", err)
	}

	return &RemediationDetails{
		Code: code,
		Steps: steps,
	}, nil
}