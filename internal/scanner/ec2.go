package scanner

import (
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/lokeshllkumar/sec-aws/internal/utils"
)

func CheckEC2Security(instanceID *string) []utils.SecurityIssue {
	cfg, ctx, err := LoadAWSConfig()
	if err != nil {
		log.Fatal("Error fetching AWS config:", err)
	}

	client := ec2.NewFromConfig(cfg)

	issues := []utils.SecurityIssue{}
	var instances []types.Instance

	// fetch instance/s
	res, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		log.Fatal("Error retrieving EC2 instances: ", err)
	}

	for _, res := range res.Reservations {
		for _, inst := range res.Instances {
			if instanceID == nil || *instanceID == *inst.InstanceId {
				instances = append(instances, inst)
			}
		}
	}

	// found no reservations to launch instances
	if len(instances) == 0 {
		log.Println("No EC2 instances found for the loaded config!")
		os.Exit(1)
	}

	for _, inst := range instances {
		fmt.Printf("Checking security for EC2 instance: %s ... \n", *inst.InstanceId)

		// checking IAM role
		if inst.IamInstanceProfile == nil {
			issues = append(issues, utils.SecurityIssue{
				Service:      "EC2",
				ResourceName: *inst.InstanceId,
				Details:      "Instance has no IAM role assigned",
				Severity:     "Medium",
			})
		}

		// checking security groups for public access
		secGroups, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
		if err == nil {
			for _, sg := range secGroups.SecurityGroups {
				for _, perm := range sg.IpPermissions {
					for _, ipRange := range perm.IpRanges {
						if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
							issues = append(issues, utils.SecurityIssue{
								Service: "EC2",
								ResourceName: *inst.InstanceId,
								Details: "Instance has open security group rules, allowing public access",
								Severity: "High",
							})
						}
					}
				}
			}
		}

		// checking unencrypted EBS volumes
		volumes, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
		if err != nil {
			for _, vol := range volumes.Volumes {
				if !*vol.Encrypted {
					issues = append(issues, utils.SecurityIssue{
						Service: "EC2",
						ResourceName: *inst.InstanceId,
						Details: "Attached EBS volume is not encrypted",
						Severity: "Medium",
					})
				}
			}
		}
	}

	return issues
}
