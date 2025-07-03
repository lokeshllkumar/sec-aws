package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lokeshllkumar/sec-aws/internal/awsclient"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
)

// rule 1 - IAM users with AdministratorAccess policy
type IAMAdminUserRule struct{}

func (r *IAMAdminUserRule) Name() string {
	return "IAM.1_AdminAccessUser"
}

func (r *IAMAdminUserRule) Description() string {
	return "Checks for IAM users with the AdministratorAccess managed policy"
}

func (r *IAMAdminUserRule) Severity() Severity {
	return SeverityCritical
}

func (r *IAMAdminUserRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	users, err := awsClient.ListIAMUsers(ctx)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		userName := *user.UserName
		attachedPolicies, err := awsClient.ListAttachedUserPolicies(ctx, userName)
		if err != nil {
			logger.Log.Warnf("Failed to list policies for user %s: %v", userName, err)
			continue
		}

		for _, policy := range attachedPolicies {
			if policy.PolicyName != nil && *policy.PolicyName == "AdministratorAccess" {
				findings = append(findings, Vulnerability{
					ID:          fmt.Sprintf("IAM.1-%s", *user.UserName),
					Name:        r.Name(),
					Description: r.Description(),
					Service:     "IAM",
					ResourceID:  userName,
					ResourceARN: *user.Arn,
					Region:      region,
					Severity:    r.Severity(),
					Details: map[string]string{
						"PolicyName": "AdministratorAccess",
						"PolicyARN":  *policy.PolicyArn,
					},
					Timestamp: time.Now().Format(time.RFC3339),
				})
				break
			}
		}
	}

	return findings, nil
}

// rule 2 - IAM users with long-lived access keys
type IAMLongLivedAccessKeyRule struct{}

func (r *IAMLongLivedAccessKeyRule) Name() string {
	return "IAM.2_LongLivedAccessKey"
}

func (r *IAMLongLivedAccessKeyRule) Description() string {
	return "Checks for IAM users with long-lived access keys (that have not been rotated in the last 90 days)"
}

func (r *IAMLongLivedAccessKeyRule) Severity() Severity {
	return SeverityMedium
}

func (r *IAMLongLivedAccessKeyRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	users, err := awsClient.ListIAMUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list IAM users: %v", err)
	}

	const maxKeyAgeDays = 90
	now := time.Now()

	for _, user := range users {
		userName := *user.UserName
		keys, err := awsClient.ListAccessKeys(ctx, userName)
		if err != nil {
			logger.Log.Warnf("Failed to list access keys for user %s: %v", userName, err)
			continue
		}

		for _, key := range keys {
			if key.CreateDate != nil {
				age := now.Sub(*key.CreateDate).Hours() / 24
				if age > maxKeyAgeDays {
					findings = append(findings, Vulnerability{
						ID:          fmt.Sprintf("IAM.2-%s", userName),
						Name:        r.Name(),
						Description: r.Description(),
						Service:     "IAM",
						ResourceID:  userName,
						ResourceARN: *user.Arn,
						Region:      region,
						Severity:    r.Severity(),
						Details: map[string]string{
							"AccessKeyId": *key.AccessKeyId,
							"CreateDate":  key.CreateDate.Format(time.RFC3339),
							"AgeDays":     fmt.Sprintf("%.0f", age),
						},
						Timestamp: time.Now().Format(time.RFC3339),
					})
				}
			}
		}
	}

	return findings, nil
}

// rule 3 - IAM account password policy not strong enough
type IAMPasswordPolicyRule struct{}

func (r *IAMPasswordPolicyRule) Name() string {
	return "IAM.3_WeakPasswordPolicy"
}

func (r *IAMPasswordPolicyRule) Description() string {
	return "Checks for IAM account password policies that do not enforce strong password requirements"
}

func (r *IAMPasswordPolicyRule) Severity() Severity {
	return SeverityHigh
}

func (r *IAMPasswordPolicyRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	policy, err := awsClient.GetAccountPasswordPolicy(ctx)
	if err != nil {
		// also check if there is no password polciy set
		if strings.Contains(err.Error(), "NoSuchEntity") {
			findings = append(findings, Vulnerability{
				ID:          "IAM.3-NoPolicy",
				Name:        r.Name(),
				Description: "No password policy set for the IAM user",
				Service:     "IAM",
				ResourceID:  "Account",
				ResourceARN: "",
				Region:      region,
				Severity:    r.Severity(),
				Details:     map[string]string{"Reason": "No password policy set"},
				Timestamp:   time.Now().Format(time.RFC3339),
			})
			return findings, nil
		}
		return nil, fmt.Errorf("failed to get account password policy: %v", err)
	}
	
	minLen := int32(14)
	requireSymbols := true
	requireNumbers := true
	requireUppercase := true
	requireLowercase := true
	maxAgeDays := int32(90)

	details := make(map[string]string)
	isWeak := false

	if policy.PasswordPolicy.MinimumPasswordLength == nil || *policy.PasswordPolicy.MinimumPasswordLength < minLen {
		isWeak = true
		details["MinimumPasswordLength"] = fmt.Sprintf("Current: %d, Recommended: %d", *policy.PasswordPolicy.MinimumPasswordLength, minLen)
	}
	if policy.PasswordPolicy.RequireSymbols != requireSymbols {
		isWeak = true
		details["RequireSymbols"] = fmt.Sprintf("Current: %t, Recommended: %t", policy.PasswordPolicy.RequireSymbols, requireSymbols)
	}
	if policy.PasswordPolicy.RequireNumbers != requireNumbers {
		isWeak = true
		details["RequireNumbers"] = fmt.Sprintf("Current: %t, Recommended: %t", policy.PasswordPolicy.RequireNumbers, requireNumbers)
	}
	if policy.PasswordPolicy.RequireUppercaseCharacters != requireUppercase {
		isWeak = true
		details["RequireUppercaseCharacters"] = fmt.Sprintf("Current: %t, Recommended: %t", policy.PasswordPolicy.RequireUppercaseCharacters, requireUppercase)
	}
	if policy.PasswordPolicy.RequireLowercaseCharacters != requireLowercase {
		isWeak = true
		details["RequireLowercaseCharacters"] = fmt.Sprintf("Current: %t, Recommended: %t", policy.PasswordPolicy.RequireLowercaseCharacters, requireLowercase)
	}
	if policy.PasswordPolicy.MaxPasswordAge == nil || *policy.PasswordPolicy.MaxPasswordAge > maxAgeDays {
		isWeak = true
		details["MaxPasswordAge"] = fmt.Sprintf("Current: %d days, Recommended: %d days or less", *policy.PasswordPolicy.MaxPasswordAge, maxAgeDays)
	}

	if isWeak {
		findings = append(findings, Vulnerability{
			ID: "IAM.3-WeakPolicy",
			Name: r.Name(),
			Description: r.Description(),
			Service: "IAM",
			ResourceID: "Account",
			ResourceARN: "",
			Region: region,
			Severity: r.Severity(),
			Details: details,
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}

	return findings, nil
}	