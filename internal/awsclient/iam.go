package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
)

// lists all IAM users on the registered account
func (c *AWSClient) ListIAMUsers(ctx context.Context) ([]types.User, error) {
	logger.Log.Debug("Listing IAM users...")
	var users []types.User
	input := &iam.ListUsersInput{}

	paginator := iam.NewListUsersPaginator(c.IAM, input)

	for paginator.HasMorePages() {
		if err := c.AcquireToken(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter error for IAM users: %w", err)
		}

		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM users: %w", err)
		}
		users = append(users, output.Users...)
	}
	logger.Log.Debugf("Found %d IAM users", len(users))
	return users, nil
}

// listing all policies attached to an IAM user
func (c *AWSClient) ListUserPolicies(ctx context.Context, userName string) ([]string, error) {
	logger.Log.Debugf("Listing policies attached to the IAM user %s", userName)
	var policyNames []string
	input := &iam.ListUserPoliciesInput{
		UserName: &userName,
	}

	paginator := iam.NewListUserPoliciesPaginator(c.IAM, input)

	for paginator.HasMorePages() {
		if err := c.AcquireToken(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter error for IAM user policies (%s): %w", userName, err)
		}

		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list policies for user %s: %w", userName, err)
		}
		policyNames = append(policyNames, output.PolicyNames...)
	}

	return policyNames, nil
}

// gets the content of a policy attached to an IAM user
func (c *AWSClient) GetUserPolicy(ctx context.Context, userName string, policyName string) (string, error) {
	logger.Log.Debugf("Getting inline policy %s for IAM user %s", policyName, userName)
	if err := c.AcquireToken(ctx); err != nil {
		return "", fmt.Errorf("rate limiter error for IAM user policy details (%s, %s): %w", userName, policyName, err)
	}

	output, err := c.IAM.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
		UserName: &userName,
		PolicyName: &policyName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get policy %s for user %s: %w", policyName, userName, err)
	}
	if output.PolicyDocument == nil {
		return "", fmt.Errorf("policy document is nil for user %s, policy %s", userName, policyName)
	}
	return *output.PolicyDocument, nil
}

// lists all managed policies attached to an IAM user
func (c *AWSClient) ListAttachedUserPolicies(ctx context.Context, userName string) ([]types.AttachedPolicy, error) {
	logger.Log.Debugf("Listing attached policies for IAM user: %s", userName)
	var policies []types.AttachedPolicy
	input := &iam.ListAttachedUserPoliciesInput{
		UserName: &userName,
	}

	paginator := iam.NewListAttachedUserPoliciesPaginator(c.IAM, input)

	for paginator.HasMorePages() {
		if err := c.AcquireToken(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter error for IAM attached user policies (%s): %w", userName, err)
		}

		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list attached policies for user %s: %w", userName, err)
		}
		policies = append(policies, output.AttachedPolicies...)
	}
	return policies, nil
}

// retrieves the content of a specific policy version
func (c *AWSClient) GetPolicyVersion(ctx context.Context, policyArn string, versionID string) (string, error) {
	logger.Log.Debugf("Getting policy version %s for policy ARN: %s", versionID, policyArn)
	if err := c.AcquireToken(ctx); err != nil {
		return "", fmt.Errorf("rate limiter error for IAM policy version (%s, %s): %w", policyArn, versionID, err)
	}

	output, err := c.IAM.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: &versionID,
	})
	if err != nil {
		return "", fmt.Errorf("faield to get policy version %s for policy ARN %s: %w", versionID, policyArn, err)
	}
	if output.PolicyVersion == nil || output.PolicyVersion.Document == nil {
		return "", fmt.Errorf("policy document is nil for policy ARN %s, version %s", policyArn, versionID)
	}

	return *output.PolicyVersion.Document, nil
}

// list the access keys for an IAM user
func (c *AWSClient) ListAccessKeys(ctx context.Context, userName string) ([]types.AccessKeyMetadata, error) {
	logger.Log.Debugf("Listing access keys for IAM user %s", userName)
	if err := c.AcquireToken(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter for IAM access keys (%s): %w", userName, err)
	}

	output, err := c.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: &userName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list access keys for user %s: %w", userName, err)
	}
	return output.AccessKeyMetadata, nil
}

// retrieves the IAM account password policy
func (c *AWSClient) GetAccountPasswordPolicy(ctx context.Context) (*iam.GetAccountPasswordPolicyOutput, error) {
	logger.Log.Debug("Getting IAM account password policy...")
	if err := c.AcquireToken(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error for IAM account password policy: %w", err)
	}

	output, err := c.IAM.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get account password policy: %w", err)
	}
	return output, nil
}