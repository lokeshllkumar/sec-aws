# script to provision a vulnerable EC2 instance with an open SSH port to the Internet and one that is publicly accessible, and a publicly accessible S3 bucket

provider "aws" {
    region = var.aws_region
}

data "aws_ami" "ubuntu_2204" {
    most_recent = true
    owners      = ["099720109477"] # AWS account ID for Ubuntu from Canonical

    filter {
        name   = "name"
        values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
    }

    filter {
        name   = "virtualization-type"
        values = ["hvm"]
    }
}

resource "aws_key_pair" "sec_aws_test_key" {
    key_name   = var.ec2_key_pair_name
    public_key = var.ec2_public_key_path != "" ? file(var.ec2_public_key_path) : null
}

# security group allowing SSH access from anywhere
resource "aws_security_group" "public_ssh_sg" {
    name        = "${var.project_prefix}-public-ssh-sg"
    description = "Security Group for public SSH access (for scanner testing)"
    vpc_id      = var.vpc_id

    ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name        = "${var.project_prefix}-PublicSSH-SG"
        Environment = "ScannerTest"
    }
}

// public EC2 instance
resource "aws_instance" "public_ubuntu_instance" {
    ami                         = data.aws_ami.ubuntu_2204.id
    instance_type               = "t2.micro"
    key_name                    = aws_key_pair.scanner_test_key.key_name
    vpc_security_group_ids      = [aws_security_group.public_ssh_sg.id]
    subnet_id                   = var.ec2_subnet_id 
    associate_public_ip_address = true              

    tags = {
        Name        = "${var.project_prefix}-PublicUbuntuTestInstance"
        Environment = "SecAwsTest"
    }
}

# S3 bukcet with public read access
resource "random_id" "bucket_suffix" {
    byte_length = 4
}

resource "aws_s3_bucket" "public_test_bucket" {
    bucket = "${var.project_prefix}-public-test-bucket-${random_id.bucket_suffix.hex}"
    acl    = "private"

    tags = {
        Name        = "${var.project_prefix}-PublicTestBucket"
        Environment = "SecAwsTest"
    }
}

resource "aws_s3_bucket_public_access_block" "public_test_bucket_pab" {
    bucket = aws_s3_bucket.public_test_bucket.id

    block_public_acls       = false
    ignore_public_acls      = false
    block_public_policy     = false
    restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read_policy" {
    bucket = aws_s3_bucket.public_test_bucket.id
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Sid       = "PublicReadGetObject"
                Effect    = "Allow"
                Principal = "*"
                Action    = ["s3:GetObject"]
                Resource  = ["${aws_s3_bucket.public_test_bucket.arn}/*"]
            },
        ]
    })
}

resource "local_file" "dummy_s3_file" {
  content  = "This is a test file for the publicly accessible S3 bucket."
  filename = "${path.module}/dummy_s3_file.txt"
}

resource "aws_s3_object" "dummy_s3_object" {
  bucket       = aws_s3_bucket.public_test_bucket.id
  key          = "test-file.txt"
  source       = "${path.module}/dummy_s3_file.txt"
  acl          = "public-read" # Make the object itself publicly readable
  content_type = "text/plain"
}   
