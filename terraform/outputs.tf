output "ec2_instance_id" {
    value = module.ec2.instance_id
}

output "s3_bucket_url" {
    value = module.s3.bucket_url
}

output "iam_user" {
    value = module.iam.iam_user
}