package remediate

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/lokeshllkumar/sec-aws/internal/pinecone"
	"github.com/lokeshllkumar/sec-aws/internal/utils"
)

type FixRequest struct {
	Context string `json:"context"`
}

type FixResponse struct {
	Fix string `json:"fix"`
}

func GenerateFix(issue utils.SecurityIssue) (*string, error) {
	context, err := pinecone.QueryIssue(issue)
	if err != nil {
		context = &utils.SecurityIssueMetadata{
			Service:      issue.Service,
			ResourceName: issue.ResourceName,
			Details:      issue.Details,
			Severity:     issue.Details,
			Fix:          "No prior fixes known/found",
		}
	}

	contextStr := context.StringifyMetadata()

	// hitting API endpoint to get fix from LLM
	url := "http://0.0.0.0:8000/fix"

	// forming request payload
	reqBody, _ := json.Marshal(FixRequest{
		Context: contextStr,
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

	var respData FixResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return &respData.Fix, nil
}
