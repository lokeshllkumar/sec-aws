package scanner

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/lokeshllkumar/sec-aws/internal/utils"
)

func CheckIAMSecurity(userName *string) []utils.SecurityIssue {
	cfg, ctx, err := LoadAWSConfig()
	if err != nil {
		log.Fatal("Error fetching AWS config:", err)
	}

	client := iam.NewFromConfig(cfg)

	issues := []utils.SecurityIssue{}
	var usersList []string
	
	// listing IAM users
	if userName == nil {
		users, err := client.ListUsers(ctx, &iam.ListUsersInput{})
		if err != nil {
			log.Fatal("Error listing IAM users: ", err)
		}

		for _, user := range users.Users {
			usersList = append(usersList, *user.UserName)
		}
	} else {
		usersList = append(usersList, *userName)
	}
	

	for _, user := range usersList {
		fmt.Printf("Checking security of user: %s ...\n", user)

		// checking if MFA is enabled
		mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: &user,
		})
		if err == nil && len(mfaDevices.MFADevices) == 0 {
			issues = append(issues, utils.SecurityIssue{
				Service: "IAM",
				ResourceName: user,
				Details: "User does not have MFA enabled",
				Severity: "High",
			})
		}

		// checking access keys
		keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: &user,
		})
		if err == nil && len(keys.AccessKeyMetadata) > 1 {
			issues = append(issues, utils.SecurityIssue{
				Service: "IAM",
				ResourceName: user,
				Details: "User multiple active access keys",
				Severity: "Medium",
			})
		}

		// checking root account access keys
		if userName == nil { // checking root account only when all users are scanned
			rootKeys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
			if err == nil && len(rootKeys.AccessKeyMetadata) > 0 {
				issues = append(issues, utils.SecurityIssue{
					Service: "IAM",
					ResourceName: "Root Account",
					Details: "Root account has active access keys",
					Severity: "Critical",
				})
			}
		}
	}
	return issues
}