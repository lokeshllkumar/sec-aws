package cmd

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lokeshllkumar/sec-aws/internal/awsclient"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
	"github.com/lokeshllkumar/sec-aws/internal/scanner"
	"github.com/lokeshllkumar/sec-aws/pkg/ai"
	"github.com/lokeshllkumar/sec-aws/pkg/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var outputFormat string
var enableAIRemediation bool

var scanCmd = &cobra.Command{
	Use: "scan",
	Short: "Scan AWS resources for vulnerabilities",
	Long: `Performs a security scan across configured AWS services (primarily EC2 instances, EBS volumes, S3 buckets, and IAM users) to identify vulnerabilities.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Minute)
		defer cancel()

		region := viper.GetString("aws.region")
		if region == "" {
			logger.Log.Fatal("AWS region is not configured. Please set the region using 'sec-aws configure' or --region flag.")
			return fmt.Errorf("AWS region not configured")
		}

		// initializing AWS client
		awsClient, err := awsclient.New(ctx, region)
		if err != nil {
			logger.Log.Fatalf("Failed to initialize AWS client: %v", err)
			return err
		}

		// initializing AI client
		aiClient := ai.NewClient()
		pineconeClient, err := ai.NewPineconeClient(
			viper.GetString("pinecone.api_key"),
			viper.GetString("pinecone.environment"),
			viper.GetString("pinecone.index"),
		)
		if err != nil {
			return fmt.Errorf("failed to initialize Pinecone client: %v", err)
		}

		// initializing the scanner
		secScanner := scanner.NewScanner(awsClient, aiClient, pineconeClient, region)

		findings, err := secScanner.RunScan(ctx)
		if err != nil {
			logger.Log.Fatalf("Scan failed: %v", err)
			return err
		}

		if enableAIRemediation {
			logger.Log.Info("Enabling AI-driven remediation suggestions for vulnerabilities")
			var wg sync.WaitGroup
			for i := range findings {
				wg.Add(1)
				go func(finding *scanner.Vulnerability) {
					defer wg.Done()
					if err := secScanner.GetRemediationSteps(ctx, finding); err != nil {
						logger.Log.WithError(err).Warnf("Failed to get remediation for finding ID %s", finding.ID)
					}
				}(&findings[i])
			}
			wg.Wait()
			logger.Log.Info("AI-driven remediation suggestions generation completed")
		}

		return output.PrintFindings(findings, output.OutputFormat(outputFormat))
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (table, json, csv)")
	scanCmd.Flags().BoolVarP(&enableAIRemediation, "ai-remediation", "a", false, "Enable AI-driven remediation suggestions for vulnerabilities")
}