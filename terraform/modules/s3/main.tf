resource "aws_s3_bucket" "vulnerable_bucket" {
    bucket = var.bucket_name
}

resource "aws_s3_bucket_acl" "public_acl" {
    bucket = aws_s3_bucket.vulnerable_bucket.id
    acl = "public-read" # publicly readable bucket
}

output "s3_bucket_name" {
    value = aws_s3_bucket.vulnerable_bucket.bucket
}