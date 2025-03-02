package utils

import "fmt"

type SecurityIssue struct {
	Service string `json:"service"`
	ResourceName string `json:"resource name"`
	Details string `json:"details"`
	Severity string `json:"severity"`
}

type SecurityIssueMetadata struct {
	Service string `json:"service"`
	ResourceName string `json:"resourcename"`
	Details string `json:"details"`
	Severity string `json:"severity"`
	Fix string `json:"fix"`
}

func(s SecurityIssue) DisplayIssue() {
	fmt.Printf("[%s] %s - %s (Severity: %s)\n", s.Service, s.ResourceName, s.Details, s.Severity)
}

func(s SecurityIssue) StringifyIssue() string {
	str := fmt.Sprintf("[%s] %s - %s (Severity: %s)\n", s.Service, s.ResourceName, s.Details, s.Severity)
	return str
}

func(m SecurityIssueMetadata) StringifyMetadata() string {
	str := fmt.Sprintf("[%s] %s - %s (Severity: %s); Fix: %s\n", m.Service, m.ResourceName, m.Details, m.Severity, m.Fix)
	return str
}