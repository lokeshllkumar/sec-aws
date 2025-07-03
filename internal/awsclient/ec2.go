package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/lokeshllkumar/sec-aws/internal/logger"
)

// lists all EC2 instances provisioned in the configured AWS region
func (c *AWSClient) EnumerateEC2Instances(ctx context.Context) ([]types.Instance, error) {
	logger.Log.Debug("Enumerating EC2 instances...")
	var instances []types.Instance
	input := &ec2.DescribeInstancesInput{}

	paginator := ec2.NewDescribeInstancesPaginator(c.EC2, input)

	for paginator.HasMorePages() {
		if err := c.AcquireToken(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter error for EC2 instances: %v", err)
		}

		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe EC2 instances: %v", err)
		}
		for _, reservation := range output.Reservations {
			instances = append(instances, reservation.Instances...)
		}
	}
	logger.Log.Debugf("Found %d EC2 instances", len(instances))
	return instances, nil
}

// lists all EC2 security groups
func (c *AWSClient) DescribeEC2SecurityGroups(ctx context.Context) ([]types.SecurityGroup, error) {
	logger.Log.Debug("Describing EC2 security groups...")
	var securityGroups []types.SecurityGroup
	input := &ec2.DescribeSecurityGroupsInput{}

	if err := c.AcquireToken(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error for EC2 security groups: %v", err)
	}

	output, err := c.EC2.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("faield to describe security groups: %v", err)
	}
	securityGroups = output.SecurityGroups
	logger.Log.Debugf("Found %d EC2 security groups", len(securityGroups))
	return securityGroups, nil
}

// lists EBS snapshots
func (c *AWSClient) DescribeEBSSnapshots(ctx context.Context) ([]types.Snapshot, error) {
	logger.Log.Debug("Describing EBS snapshots...")
	var snapshots []types.Snapshot
	input := &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"}, // snapshots owned by the current account
	}

	paginator := ec2.NewDescribeSnapshotsPaginator(c.EC2, input)

	for paginator.HasMorePages() {
		if err := c.AcquireToken(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter errror for EBS snapshots: %v", err)
		}

		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe EBS snapshots: %v", err)
		}
		snapshots = append(snapshots, output.Snapshots...)
	}
	logger.Log.Debugf("Found %d EBS snapshots", len(snapshots))
	return snapshots, nil
}

// lists EBS volumes

func (c *AWSClient) DescribeEBSVolumes(ctx context.Context) ([]types.Volume, error) {
	logger.Log.Debug("Describing EBS volumes...")
	var volumes []types.Volume
	input := &ec2.DescribeVolumesInput{}

	paginator := ec2.NewDescribeVolumesPaginator(c.EC2, input)

	for paginator.HasMorePages() {
		if err := c.AcquireToken(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter error for EBS volumes: %v", err)
		}

		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe EBS volumes: %v", err)
		}
		volumes = append(volumes, output.Volumes...)
	}
	logger.Log.Debugf("Found %d EBS volumes", len(volumes))
	return volumes, nil
}