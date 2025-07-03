package awsclient

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/lokeshllkumar/sec-aws/internal/logger"
	"golang.org/x/time/rate"
)

// AWS service clients and a rate limiter for each
type AWSClient struct {
	EC2 *ec2.Client
	S3  *s3.Client
	IAM *iam.Client

	limiter *rate.Limiter // rate limiter for AWS API calls
	mu      sync.Mutex    // to protect concurrent access to resources and the rate limiter
}

// initializes a new client
func New(ctx context.Context, region string) (*AWSClient, error) {
	config, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("faield to load default AWS SDK config: %w", err)
	}

	limiter := rate.NewLimiter(rate.Every(1*time.Second/10), 20)

	return &AWSClient{
		EC2:     ec2.NewFromConfig(config),
		S3:      s3.NewFromConfig(config),
		IAM:     iam.NewFromConfig(config),
		limiter: limiter,
	}, nil
}

// waits till token is acquired for the rate limiter
func (c *AWSClient) AcquireToken(ctx context.Context) error {
	logger.Log.Debug("Acquiring rate limiter token...")
	err := c.limiter.Wait(ctx)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to acquire rate limiter token")
	}

	return err

}
