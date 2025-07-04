output "ec2_instance_id" {
    description = "ID of the provisioned EC2 instance"
    value       = aws_instance.public_ubuntu_instance.id
}

output "ec2_public_ip" {
    description = "Public IP address of the EC2 instance"
    value       = aws_instance.public_ubuntu_instance.public_ip
}

output "ec2_security_group_id" {
    description = "ID of the security group attached to the EC2 instance"
    value       = aws_security_group.public_ssh_sg.id
}

output "s3_bucket_name" {
    description = "Name of the publicly accessible S3 bucket"
    value       = aws_s3_bucket.public_test_bucket.bucket
}

output "s3_dummy_file_url" {
    description = "URL to the dummy file in the S3 bucket; verify public access"
    value       = "https://${aws_s3_bucket.public_test_bucket.bucket}.s3.${var.aws_region}.amazonaws.com/${aws_s3_object.dummy_s3_object.key}"
}

output "security_warning" {
    description = "WARNING: The resources are insecure by design and for testing purposes only"
    value       = "The EC2 instance has SSH open to the internet and the S3 bucket is publicly readable"
}
