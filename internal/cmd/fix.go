package cmd

import (
	"fmt"

	"github.com/lokeshllkumar/sec-aws/internal/pinecone"
	"github.com/lokeshllkumar/sec-aws/internal/remediate"
	"github.com/lokeshllkumar/sec-aws/internal/scanner"
	"github.com/lokeshllkumar/sec-aws/internal/utils"
	"github.com/spf13/cobra"
)

var FixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Generate fixes for detected AWS security issues",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Scanning all AWS services for vulnerabilites...")
		var issues []utils.SecurityIssue
		issues = append(issues, scanner.CheckEC2Security(nil)...)
		issues = append(issues, scanner.CheckS3BucketSecurity(nil)...)
		issues = append(issues, scanner.CheckIAMSecurity(nil)...)

		if len(issues) == 0 {
			fmt.Println("No security issue found")
			return
		}

		fmt.Printf("Found %d security issues. Generating Fixes...", len(issues))

		for _, issue := range issues {
			fix, err := remediate.GenerateFix(issue)
			if err != nil {
				fmt.Printf("Unable to generate fix for resource %s (%s)\n", issue.ResourceName, issue.Service)
				continue
			}
			fmt.Printf("Fix for %s (%s): %s\n", issue.ResourceName, issue.Service, *fix)
			pinecone.UpsertIssue(issue, *fix)
		}
	},
}
