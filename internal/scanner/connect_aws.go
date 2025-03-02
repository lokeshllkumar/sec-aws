package scanner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/lokeshllkumar/sec-aws/internal/utils"
)

func LoadAWSConfig() (aws.Config, context.Context, error) {
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, 
		config.WithRegion(utils.AwsRegion), 
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID: utils.AwsAccessKey,
				SecretAccessKey: utils.AwsSecretKey,
				SessionToken: "",
				Source: "Hardcoded",
			},
		},
	))
	if err != nil {
		return aws.Config{}, nil, err
	}

	return cfg, ctx, nil
}
