variable "aws_region" {
    description = "AWS region"
    type = string
    default = "ap-south-1"   
}

variable "instance_type" {
    description = "EC2 instance type"
    type = string
    default = "t2.micro"
}

variable "bucket_name" {
    description = "S3 bucket name"
    type = string
}

variable "iam_user" {
    description = "IAM user with excessive permissions"
    type = string
    default = "vulnerable-user"
}