package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/lokeshllkumar/sec-aws/internal/awsclient"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
)

// type 1 - open SSH port to the Internet
type EC2OpenSSHRule struct{}

func (r *EC2OpenSSHRule) Name() string {
	return "EC2.1_OpenSSHToInternet"
}

func (r *EC2OpenSSHRule) Description() string {
	return "Checks for EC2 security groups allowing SSH (port 22) from anywhere (0.0.0.0/0)"
}

func (r *EC2OpenSSHRule) Severity() Severity {
	return SeverityCritical
}

func (r *EC2OpenSSHRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	secGroups, err := awsClient.DescribeEC2SecurityGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %v", err)
	}

	for _, secGroup := range secGroups {
		for _, ipPerm := range secGroup.IpPermissions {
			// checking TCP port 22
			if ipPerm.FromPort != nil && ipPerm.ToPort != nil && *ipPerm.FromPort <= 22 && *ipPerm.ToPort >= 22 && strings.ToUpper(string(*ipPerm.IpProtocol)) == "TCP" {
				for _, ipRange := range ipPerm.IpRanges {
					if ipRange.CidrIp != nil && (*ipRange.CidrIp == "0.0.0.0/0" || *ipRange.CidrIp == "::/0") {
						findings = append(findings, Vulnerability{
							ID:          fmt.Sprintf("EC2.1-%s-%s", *secGroup.GroupId, "SSH_Open_Internet"),
							Name:        r.Name(),
							Description: r.Description(),
							Service:     "EC2",
							ResourceID:  *secGroup.GroupId,
							ResourceARN: "", // needs to be constructed
							Region:      region,
							Severity:    r.Severity(),
							Details: map[string]string{
								"SecurityGroupName": *secGroup.GroupName,
								"Protocol":          *ipPerm.IpProtocol,
								"Port":              "22",
								"SourceCidr":        *ipRange.CidrIp,
							},
							Timestamp: time.Now().Format(time.RFC3339),
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}

// type 2 - public EC2 instances
type EC2PublicInstanceRule struct{}

func (r *EC2PublicInstanceRule) Name() string {
	return "EC2.2_ PublicInstance"
}

func (r *EC2PublicInstanceRule) Description() string {
	return "Checks for EC2 instances with a public IP address"
}

func (r *EC2PublicInstanceRule) Severity() Severity {
	return SeverityMedium
}

func (r *EC2PublicInstanceRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	instances, err := awsClient.EnumerateEC2Instances(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate EC2 instances: %v", err)
	}

	for _, instance := range instances {
		if instance.PublicIpAddress != nil && *instance.PublicIpAddress != "" && instance.State.Name == types.InstanceStateNameRunning {
			findings = append(findings, Vulnerability{
				ID:          fmt.Sprintf("EC2.2-%s", *instance.InstanceId),
				Name:        r.Name(),
				Description: r.Description(),
				Service:     "EC2",
				ResourceID:  *instance.InstanceId,
				ResourceARN: "",
				Region:      region,
				Severity:    r.Severity(),
				Details: map[string]string{
					"PublicIpAddress": *instance.PublicIpAddress,
					"InstanceType":    string(instance.InstanceType),
					"State":           string(instance.State.Name),
				},
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}

	return findings, nil
}

// type 3 - unencrypted EBS volumes
type EBSUnencryptedRule struct{}

func (r *EBSUnencryptedRule) Name() string {
	return "EC2.3_EBSUnencrypted"
}

func (r *EBSUnencryptedRule) Description() string {
	return "Checks for unencrypted EBS volumes"
}

func (r *EBSUnencryptedRule) Severity() Severity {
	return SeverityHigh
}

func (r *EBSUnencryptedRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	volumes, err := awsClient.DescribeEBSVolumes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to describe EBS volumes: %v", err)
	}

	for _, volume := range volumes {
		if volume.Encrypted == nil || !*volume.Encrypted {
			findings = append(findings, Vulnerability{
				ID:          fmt.Sprintf("EC2.3-%s", *volume.VolumeId),
				Name:        r.Name(),
				Description: r.Description(),
				Service:     "EBS",
				ResourceID:  *volume.VolumeId,
				ResourceARN: "",
				Region:      region,
				Severity:    r.Severity(),
				Details: map[string]string{
					"VolumeState": string(volume.State),
					"VolumeType":  string(volume.VolumeType),
					"SizeGB":      fmt.Sprintf("%d", *volume.Size),
				},
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}

	return findings, nil
}

// rule 4 - publicly accessible EBS snapshots
type EBSSnapshotPublicRule struct{}

func (r *EBSSnapshotPublicRule) Name() string {
	return "EC2.4_EBSSnapshotPublic"
}

func (r *EBSSnapshotPublicRule) Description() string {
	return "Checks for EBS snapshots that are publicly accessible"
}

func (r *EBSSnapshotPublicRule) Severity() Severity {
	return SeverityCritical
}

func (r *EBSSnapshotPublicRule) Check(ctx context.Context, awsClient *awsclient.AWSClient, region string) ([]Vulnerability, error) {
	var findings []Vulnerability
	input := &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
		Filters: []types.Filter{
			{
				Name:   aws.String("status"),
				Values: []string{string(types.SnapshotStateCompleted)},
			},
		},
	}
	paginator := ec2.NewDescribeSnapshotsPaginator(awsClient.EC2, input)

	for paginator.HasMorePages() {
		if err := awsClient.AcquireToken(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter error for EBS snapshots: %v", err)
		}

		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe EBS snapshots: %v", err)
		}
		for _, snapshot := range output.Snapshots {
			if snapshot.SnapshotId == nil || *snapshot.SnapshotId == "" {
				logger.Log.Warn("Encountered a snapshot with a nil or empty SnapshotId. Skipping this malformed entry.")
				continue
			}

			if err := awsClient.AcquireToken(ctx); err != nil {
				logger.Log.WithError(err).Warnf("Rate limiter error before checking snaphsot attribute for %s. Skipping attribute check for the current snapshot...", *snapshot.SnapshotId)
				continue
			}

			attrInput := &ec2.DescribeSnapshotAttributeInput{
				SnapshotId: snapshot.SnapshotId,
				Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
			}

			attrOutput, err := awsClient.EC2.DescribeSnapshotAttribute(ctx, attrInput)
			if err != nil {
				logger.Log.WithError(err).Warnf("Failed to describe CreateVolumePermission attribute for snapshot %s. Skipping...", *snapshot.SnapshotId)
				continue
			}

			for _, perm := range attrOutput.CreateVolumePermissions {
				if perm.Group == types.PermissionGroupAll {
					findings = append(findings, Vulnerability{
						ID:          fmt.Sprintf("EC2.4-%s", *snapshot.SnapshotId),
						Name:        r.Name(),
						Description: r.Description(),
						Service:     "EBS",
						ResourceID:  *snapshot.SnapshotId,
						ResourceARN: "",
						Region:      region,
						Severity:    r.Severity(),
						Details: map[string]string{
							"SnapshotId":      *snapshot.SnapshotId,
							"State":           string(snapshot.State),
							"Encrypted":       fmt.Sprintf("%t", *snapshot.Encrypted),
							"SnapshotOwnerId": *snapshot.OwnerId,
						},
						Timestamp: time.Now().Format(time.RFC3339),
					})
					break
				}
			}
		}
	}

	return findings, nil
}
