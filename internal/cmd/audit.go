package cmd

import (
	"fmt"
	"log"

	"github.com/lokeshllkumar/sec-aws/internal/scanner"
	"github.com/lokeshllkumar/sec-aws/internal/utils"
	"github.com/spf13/cobra"
)

var (
	allServices bool
	service     string
	identifier   string
)

var AuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Scan AWS for security vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		if allServices && service != "" {
			log.Fatal("Error: Cannot specify both --all and --service at the same time")
		}
		
		// complete scan
		if allServices {
			fmt.Println("Scanning all AWS services for vulnerabilites...")
			var issues []utils.SecurityIssue
			issues = append(issues, scanner.CheckEC2Security(nil)...)
			issues = append(issues, scanner.CheckS3BucketSecurity(nil)...)
			issues = append(issues, scanner.CheckIAMSecurity(nil)...)

			for _, issue := range issues {
				issueStr := issue.StringifyIssue()
				fmt.Println(issueStr)
			}

			return
		}

		// specific scan
		if service == "" {
			log.Fatalf("Error: Must specify either --all or --service")
		}

		fmt.Printf("Scanning %s...", service)
		if identifier != "" {
			fmt.Printf(" (Target: %s)", identifier)
		}
		fmt.Println(" for vulnerabilities...")

		var issues []utils.SecurityIssue

		if service == "ec2" {
			if identifier != "" {
				issues = scanner.CheckEC2Security(&identifier)
			} else {
				issues = scanner.CheckEC2Security(nil)
			}
		} else if service == "s3" {
			if identifier != "" {
				issues = scanner.CheckEC2Security(&identifier)
			} else {
				issues = scanner.CheckEC2Security(nil)
			}
		} else if service == "iam" {
			if identifier != "" {
				issues = scanner.CheckEC2Security(&identifier)
			} else {
				issues = scanner.CheckEC2Security(nil)
			}
		} else {
			log.Fatalf("Error: Invalid service specified")
		}

		for _, issue := range issues {
			issueStr := issue.StringifyIssue()
			fmt.Println(issueStr)
		}
	},
}

func init() {
	AuditCmd.Flags().BoolVarP(&allServices, "all", "a", false, "Scan all AWS services")
	AuditCmd.Flags().StringVarP(&service, "service", "s", "", "Specify the AWS service to be scanned (eg.: ec2, s3, or iam in lowercase)")
	AuditCmd.Flags().StringVarP(&identifier, "identifier", "i", "", "Optional: EC2 Instance ID, S3 Bucket Name, or IAM username")

	AuditCmd.MarkFlagsMutuallyExclusive("all", "service")
}	