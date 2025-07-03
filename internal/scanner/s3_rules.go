package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lokeshllkumar/sec-aws/internal/awsclient"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
)

// rule 1 - publicly accessible S3 buckets
type S3PublicBucketRule struct{}

func (r *S3PublicBucketRule) Name() string {
	return "S3.1_PublicBucket"
}

func (r *S3PublicBucketRule) Description() string {
	return "Checks for S3 buckets that are publicly accessible via ACLs or bucket policies"
}

func (r *S3PublicBucketRule) Severity() Severity {
	return SeverityCritical
}

func (r *S3PublicBucketRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	buckets, err := awsClient.ListS3Buckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %v", err)
	}

	for _, bucket := range buckets {
		bucketName := *bucket.Name
		isPublic := false
		publicAccessDetails := make(map[string]string)

		// checking ACLs
		aclOutput, err := awsClient.GetS3BucketACL(ctx, bucketName)
		if err != nil {
			logger.Log.Warnf("Could not get ACL for bucket %s: %v", bucketName, err)
		} else {
			for _, grant := range aclOutput.Grants {
				if grant.Grantee != nil && grant.Grantee.URI != nil {
					if *grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" ||
						*grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
						isPublic = true
						publicAccessDetails["ACL_Public_Grantee"] = *grant.Grantee.URI
						publicAccessDetails["ACL_Permission"] = string(grant.Permission)
						break
					}
				}
			}
		}

		// checking policies
		if !isPublic {
			policyOutput, err := awsClient.GetS3BucketPolicy(ctx, bucketName)
			if err != nil {
				logger.Log.Debugf("No policy found for bucket %s or failed to retrieve policies: %v", bucketName, err)
			} else if policyOutput.Policy != nil {
				policyStr := *policyOutput.Policy
				if strings.Contains(policyStr, `"Principal":"*"`) || strings.Contains(policyStr, `"Principal:{"AWS":"*"}"`) {
					isPublic = true
					publicAccessDetails["Policy_Public_Principal"] = "*"
				}
			}
		}
		
		if isPublic {
			findings = append(findings, Vulnerability{
				ID: fmt.Sprintf("S3.1-%s", bucketName),
				Name: r.Name(),
				Description: r.Description(),
				Service: "S3",
				ResourceID: bucketName,
				ResourceARN: "",
				Region: region,
				Severity: r.Severity(),
				Details: publicAccessDetails,
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}

	return findings, nil
}

// rule 2 - S3 buckets with versioning disabled
type S3VersioningDisabledRule struct{}

func (r *S3VersioningDisabledRule) Name() string {
	return "S3.2_VersioningDisabled"
}

func (r *S3VersioningDisabledRule) Description() string {
	return "Checks for S3 buckets that have versioning disabled"
}

func (r *S3VersioningDisabledRule) Severity() Severity {
	return SeverityMedium
}

func (r *S3VersioningDisabledRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {	
	var findings []Vulnerability
	buckets, err := awsClient.ListS3Buckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %v", err)
	}

	for _, bucket := range buckets {
		bucketName := *bucket.Name
		versioningOutput, err := awsClient.GetS3BucketVersioning(ctx, bucketName)
		if err != nil {
			logger.Log.Warnf("Could not get versioning status for bucket %s: %v", bucketName, err)
			continue
		}

		if versioningOutput.Status == types.BucketVersioningStatusSuspended || versioningOutput.Status != "" {
			findings = append(findings, Vulnerability{
				ID: fmt.Sprintf("S3.2-%s", bucketName),
				Name: r.Name(),
				Description: r.Description(),
				Service: "S3",
				ResourceID: bucketName,
				ResourceARN: "",
				Region: region,
				Severity: r.Severity(),
				Details: map[string]string{
					"VersioningStatus": string(versioningOutput.Status),
				},
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}

	return findings, nil
}

// rule 3 - S3 buckets without default encryption
type S3EncryptionDisabledRule struct{}

func (r *S3EncryptionDisabledRule) Name() string {
	return "S3.3_EncryptionDisabled"
}

func (r *S3EncryptionDisabledRule) Description() string {
	return "Checks for S3 buckets that do not have default encryption enabled"
}

func (r *S3EncryptionDisabledRule) Severity() Severity {
	return SeverityHigh
}

func (r *S3EncryptionDisabledRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	buckets, err := awsClient.ListS3Buckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %v", err)
	}

	for _, bucket := range buckets {
		bucketName := *bucket.Name
		encryptionOutput, err := awsClient.GetS3BucketEncryption(ctx, bucketName)
		if err != nil {
			if strings.Contains(err.Error(), "ServerSideEncryptionConfigurationNotFoundError") {
				findings = append(findings, Vulnerability{
					ID: fmt.Sprintf("S3.3-%s", bucketName),
					Name: r.Name(),
					Description: r.Description(),
					Service: "S3",
					ResourceID: bucketName,
					ResourceARN: "",
					Region: region,
					Severity: r.Severity(),
					Details: map[string]string{
						"EncryptionStatus": "Disabled",
					},
					Timestamp: time.Now().Format(time.RFC3339),
				})
			} else {
				logger.Log.Warnf("Could not get encryption status for bucket %s: %v", bucketName, err)
			}
			continue
		}

		if encryptionOutput.ServerSideEncryptionConfiguration == nil || len(encryptionOutput.ServerSideEncryptionConfiguration.Rules) == 0 {
			findings = append(findings, Vulnerability{
				ID: fmt.Sprintf("S3.3-%s-Misconfigured", bucketName),
				Name: r.Name(),
				Description: r.Description(),
				Service: "S3",
				ResourceID: bucketName,
				ResourceARN: "",
				Region: region,
				Severity: r.Severity(),
				Details: map[string]string{
					"EncryptionStatus": "Misconfigured or empty rules",
				},
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}

	return findings, nil
}
	