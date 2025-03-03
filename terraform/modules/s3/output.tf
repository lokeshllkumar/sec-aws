output "bucket_url" {
    value = "https://${aws_s3_bucket.vulnerable_bucket.bucket}.s3.amazonaws.com"
}