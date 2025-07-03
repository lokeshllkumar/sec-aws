package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lokeshllkumar/sec-aws/internal/awsclient"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
	"github.com/lokeshllkumar/sec-aws/pkg/ai"
)

// orchestrates the security scanning process
type Scanner struct {
	awscClient     *awsclient.AWSClient
	aiClient       *ai.Client
	pineconeClient ai.PineconeClient
	region         string
	rules          []VulnerabilityRule
}

// creates a new Scanner instance
func NewScanner(awsClient *awsclient.AWSClient, aiClient *ai.Client, pineconeClient ai.PineconeClient, region string) *Scanner {
	s := &Scanner{
		awscClient:     awsClient,
		aiClient:       aiClient,
		pineconeClient: pineconeClient,
		region:         region,
	}
	s.RegisterDefaultRules()

	return s
}

func (s *Scanner) RegisterDefaultRules() {
	s.rules = []VulnerabilityRule{
		// EC2 rules
		&EC2OpenSSHRule{},
		&EC2PublicInstanceRule{},
		&EBSUnencryptedRule{},
		&EBSSnapshotPublicRule{},
		// S3 rules
		&S3PublicBucketRule{},
		&S3VersioningDisabledRule{},
		&S3EncryptionDisabledRule{},
		// IAM rules
		&IAMAdminUserRule{},
		&IAMLongLivedAccessKeyRule{},
		&IAMPasswordPolicyRule{},
	}
	logger.Log.Debugf("Registered %d default rules", len(s.rules))
}

func (s *Scanner) RunScan(ctx context.Context) ([]Vulnerability, error) {
	logger.Log.Info("Starting security scan...")
	var allFindings []Vulnerability
	var m sync.Mutex
	var wg sync.WaitGroup

	for _, rule := range s.rules {
		wg.Add(1)
		go func(rule VulnerabilityRule) {
			defer wg.Done()
			logger.Log.Debugf("Running rule: %s (%s)", rule.Name(), rule.Description())
			findings, err := rule.Check(ctx, s.awscClient, s.region)
			if err != nil {
				logger.Log.Errorf("Error running rule %s: %v", rule.Name(), err)
				return
			}
			m.Lock()
			allFindings = append(allFindings, findings...)
			m.Unlock()
			logger.Log.Debugf("Rule %s completed execution with %d findings", rule.Name(), len(findings))
		}(rule)
	}

	wg.Wait()
	logger.Log.Infof("Security scan completed with %d total findings", len(allFindings))
	return allFindings, nil
}

// retrieve relevant remediation steps for a specific vulnerability finding detected
func (s *Scanner) GetRemediationSteps(ctx context.Context, finding *Vulnerability) error {
	logger.Log.WithField("finding_id", finding.ID).Info("Retrieving AI remediation steps for finding")

	// generating embeddings for the finding
	findingText := fmt.Sprintf("Vulnerability: %s, Description: %s, Service: %s, ResourceID: %s, Region: %s, Severity: %s", 
			finding.Name, finding.Description, finding.Service, finding.ResourceID, finding.Region, finding.Severity)
	queryEmbedding, err := s.aiClient.GetEmbeddings(ctx, findingText)
	if err != nil {
		logger.Log.WithField("finding_id", finding.ID).Errorf("Failed to generate query embeddings: %v", err)
		return fmt.Errorf("failed to generate query embeddings: %w", err)
	}

	// query Pinecone for relevant context
	topK := 5
	queryResult, err := s.pineconeClient.Query(ctx, queryEmbedding, topK)
	if err != nil {
		logger.Log.WithField("finding_id", finding.ID).Errorf("Failed to query Pinecone: %v", err)
		return fmt.Errorf("failed to query Pinecone: %w", err)
	}

	// building prompt for LLM
	promptBuilder := strings.Builder{}
	promptBuilder.WriteString("You are a security expert providing clear steps for remediation and advice for AWS vulnerabilities\n")
	promptBuilder.WriteString(fmt.Sprintf("Vulnerability Detected:\nRule: %s\nDescription: %s\nResource: %s (%s)\nSeverity: %s\n\n",
			finding.Name, finding.Description, finding.ResourceID, finding.Service, finding.Severity))
	if len(queryResult.Matches) > 0 {
		promptBuilder.WriteString("some similar remediation examples from a knowledge base:\n")
		for i, match := range queryResult.Matches {
			if text, ok := match.Metadata["text"].(string); ok {
				promptBuilder.WriteString(fmt.Sprintf("Example %d:\n%s\n\n", i + 1, text))
			} else {
				logger.Log.Warnf("Pinecone match metadata 'text' not found or not a string for match ID: %s", match.ID)
			}
		}
	}
	promptBuilder.WriteString("Based on the vulnerability and examples, provide a clear, concise remediation with:\n")
	promptBuilder.WriteString("1. Numbered or bulleted step-by-step instructions\n")
	promptBuilder.WriteString("2. A code block (e.g., AWS CLI, CloudFormation, Terraform) for automation, if applicable. Use standard Markdown for code blocks (e.g., ```awscli\n...code...\n``` or ```terraform\n...code...\n```)\n")
	promptBuilder.WriteString("3. Ensure the response is directly actionable for an AWS administrator\n")

	llmPrompt := promptBuilder.String()
	logger.Log.WithField("finding_id", finding.ID).Debugf("LLM Prompt:\n%s", llmPrompt)
	
	// retrieving LLM response
	llmResponse, err := s.aiClient.GetLLMResponse(ctx, llmPrompt)
	if err != nil {
		logger.Log.WithField("finding_id", finding.ID).Errorf("Failed to get LLM response: %v", err)
		return fmt.Errorf("failed to get LLM response: %w", err)
	}
	logger.Log.WithField("finding_id", finding.ID).Debugf("LLM Response:\n%s", llmResponse)

	remediationDetails, err := ai.GetRemediation(llmResponse)
	if err != nil {
		logger.Log.WithField("finding_id", finding.ID).Errorf("Failed to parse LLM response for finding %s: %v", finding.ID, err)
		return fmt.Errorf("failed to parse LLM response: %w", err)
	}

	finding.AIRemediation = llmResponse
	finding.RemediationSteps = remediationDetails.Steps
	finding.RemediationCode = remediationDetails.Code

	// upserting the newly generated remediation data for Pinecone metadata
	remediationVectorID := fmt.Sprintf("remediation-%s-%d", finding.ID, time.Now().UnixNano())

	remediationMetadata := map[string]interface{}{
		"original_finding_id": finding.ID,
		"original_finding_name": finding.Name,
		"original_description": finding.Description,
		"service": finding.Service,
		"resource_id": finding.ResourceID,
		"severity": string(finding.Severity),
		"remediation_code": remediationDetails.Code,
		"remediation_steps": strings.Join(remediationDetails.Steps, "\n"),
		"text": fmt.Sprintf("Vulnerability: %s.\n Remediation steps: %s\nCode: %s", findingText, strings.Join(remediationDetails.Steps, "\n"), remediationDetails.Code),
	}

	remediationVector := ai.PineconeVector{
		ID: remediationVectorID,
		Values: queryEmbedding,
		Metadata: remediationMetadata,
	}

	if err := s.pineconeClient.Upsert(ctx, []ai.PineconeVector{remediationVector}); err != nil {
		logger.Log.WithField("finding_id", finding.ID).WithError(err).Warn("Failed to upsert AI remediation to Pinecone")
	} else {
		logger.Log.WithField("finding_id", finding.ID).Infof("Successfully upserted AI remediation to Pinecone with ID: %s", remediationVectorID)
	}

	logger.Log.WithField("finding_id", finding.ID).Info("Successfully retrieved AI remediation steps")
	return nil
}
