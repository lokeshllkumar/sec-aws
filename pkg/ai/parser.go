package ai

import (
	"regexp"
	"strings"
)

var codeBlockRegex = regexp.MustCompile("```(?:[a-zA-Z0-9_-]*)\n(.*?)```")

var listItemRegex = regexp.MustCompile(`(?m)^\s*[\d\*\-]+\s+(.*)$`)

// extracts content of the first Markdown code block from the generated remediation by the LLM
func parseCode(llmResponse string) (string, error) {
	matches := codeBlockRegex.FindStringSubmatch(llmResponse)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1]), nil
	}
	return "", nil // if no code block is found
}

// extract a list of steps from the LLM response
func parseSteps(llmResponse string) ([]string, error) {
	var steps []string
	matches := listItemRegex.FindAllStringSubmatch(llmResponse, -1)
	for _, match := range matches {
		if len(match) > 1 {
			steps = append(steps, strings.TrimSpace(match[1]))
		}
	}
	return steps, nil
}