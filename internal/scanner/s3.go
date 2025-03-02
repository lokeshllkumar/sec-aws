package scanner

import (
	_ "context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/lokeshllkumar/sec-aws/internal/utils"
)

func CheckS3BucketSecurity(bucketName *string) []utils.SecurityIssue {
	cfg, ctx, err := LoadAWSConfig()
	if err != nil {
		log.Fatal("Error fetching AWS config:", err)
	}

	client := s3.NewFromConfig(cfg)

	issues := []utils.SecurityIssue{}
	var buckets []string

	// fetch bucket/s
	if bucketName == nil {
		listBuckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			log.Fatal("Error listing S3 buckets: ", err)
		}

		if len(listBuckets.Buckets) == 0 {
			log.Println("No S3 buckets found for the loaded config!")
			os.Exit(1)
		}

		for _, bucket := range listBuckets.Buckets {
			buckets = append(buckets, *bucket.Name)
		}
	} else {
		buckets = append(buckets, *bucketName)
	}

	for _, bucket := range buckets {
		fmt.Printf("Checking security of bucket: %s ...\n", bucket)

		// checking public access block
		pubAccess, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: &bucket,
		})
		if err != nil || pubAccess.PublicAccessBlockConfiguration == nil {
			issues = append(issues, utils.SecurityIssue{
				Service:      "S3",
				ResourceName: bucket,
				Details:      "Public access block is missing",
				Severity:     "High",
			})
		}

		// checking encryption
		_, err = client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: &bucket,
		})
		if err != nil {
			issues = append(issues, utils.SecurityIssue{
				Service:      "S3",
				ResourceName: bucket,
				Details:      "Bucket encryption is not enabled",
				Severity:     "Medium",
			})
		}

		// checking access logging
		logging, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: &bucket,
		})
		if err != nil || logging.LoggingEnabled == nil {
			issues = append(issues, utils.SecurityIssue{
				Service:      "S3",
				ResourceName: bucket,
				Details:      "Access logging is not enabled",
				Severity:     "Low",
			})
		}
	}

	return issues
}
