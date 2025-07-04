variable "aws_region" {
    description = "The AWS region for resource deployment"
    type        = string
    default     = "ap-south-1"
}

variable "project_prefix" {
    description = "Prefix for naming resources"
    type        = string
    default     = "sec-aws-test"
}

variable "vpc_id" {
    description = "ID of the VPC to deploy the EC2 instance into; leave empty to use the default VPC"
    type        = string
    default     = ""
}

variable "ec2_subnet_id" {
    description = "ID of a public subnet for the EC2 instance; leave empty to let AWS choose from default VPC"
    type        = string
    default     = ""
}

variable "ec2_key_pair_name" {
    description = "Name of the EC2 Key Pair for SSH; must exist in AWS console"
    type        = string
    default     = "" // set the name of the key pair here
}

variable "ec2_public_key_path" {
    description = "Path to your SSH public key file (e.g., ~/.ssh/id_rsa.pub); required for SSH access"
    type        = string
    default     = "" // set the path to the key file 
}
