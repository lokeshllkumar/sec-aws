package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
)

// lists S3 buckets configured on the account
func (c *AWSClient) ListS3Buckets(ctx context.Context) ([]types.Bucket, error) {
	logger.Log.Debug("Listing S3 buckets...")
	if err := c.AcquireToken(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error for S3 buckets: %v", err)
	}

	output, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %v", err)
	}
	logger.Log.Debugf("Found %d S3 buckets", len(output.Buckets))
	return output.Buckets, nil
}

// retrieves the ACL for an S3 bucket
func (c *AWSClient) GetS3BucketACL(ctx context.Context, bucketName string) (*s3.GetBucketAclOutput, error) {
	logger.Log.Debugf("Getting ACL for S3 bucket %s...", bucketName)
	if err := c.AcquireToken(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error for S3 bucket ACL (%s): %v", bucketName, err)
	}
	
	output, err := c.S3.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get ACL for bucket %s: %v", bucketName, err)
	}
	return output, nil
}

// retrieves the policy for a specific bucket
func (c *AWSClient) GetS3BucketPolicy(ctx context.Context, bucketName string) (*s3.GetBucketPolicyOutput, error) {
	logger.Log.Debugf("Getting policy for S3 bucket %s", bucketName)
	if err := c.AcquireToken(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error for S3 bucket policy (%s): %v", bucketName, err)
	}

	output, err := c.S3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy for bucket %s: %v", bucketName, err)
	}
	return output, nil
}

// retrieves encryption config for a specific S3 bucket
func (c *AWSClient) GetS3BucketEncryption(ctx context.Context, bucketName string) (*s3.GetBucketEncryptionOutput, error) {
	logger.Log.Debugf("Getting encryption for S3 bucket: %s", bucketName)
	if err := c.AcquireToken(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error for S3 bucket encryption (%s): %v", bucketName, err)
	}

	output, err := c.S3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption for bucket %s: %v", bucketName, err)
	}
	return output, nil
}

// retrieves the versioning config for an S3 bucket
func (c *AWSClient) GetS3BucketVersioning(ctx context.Context, bucketName string) (*s3.GetBucketVersioningOutput, error) {
	logger.Log.Debugf("Getting versioning for S3 bucket: %s", bucketName)
	if err := c.AcquireToken(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter for S3 bucket versioning (%s): %v", bucketName, err)
	}

	output, err := c.S3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get versioning for bucket %s: %v", bucketName, err)
	}
	return output, err
}