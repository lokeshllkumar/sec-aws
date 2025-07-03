package scanner

import (
	"context"

	"github.com/lokeshllkumar/sec-aws/internal/awsclient"
)

// represents the severity of a vulnerability
type Severity string

const SeverityCritical Severity = "CRITICAL"
const SeverityHigh Severity = "HIGH"
const SeverityMedium Severity = "MEDIUM"
const SeverityLow Severity = "LOW"
const SeverityInfo Severity = "INFO"

// represents a security finding
type Vulnerability struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Description string `json:"description"`
	Service string `json:"service"`
	ResourceID string `json:"resource_id"`
	ResourceARN string `json:"resource_arn"`
	Region string `json:"region"`
	Severity Severity `json:"severity"`
	Details map[string]string `json:"details"`
	RemediationID string `json:"remediation_id"`
	AIRemediation string `json:"ai_remediation,omitempty"`
	RemediationCode string `json:"remediation_code,omitempty"`
	RemediationSteps []string `json:"remediation_steps,omitempty"`
	Timestamp string `json:"timestamp"`
}

// suggested fix for a vulnerability finding
type Remediation struct {
	ID string `json:"id"`
	Description string `json:"description"`
	Steps []string `json:"steps"`
	CodeSnippets string `json:"code_snippets"`
	Impact string `json:"impact"`
	Tags []string `json:"tags"`
}

// defines interface for a security rule
type VulnerabilityRule interface {
	Name() string
	Description() string
	Severity() Severity
	Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error)
}