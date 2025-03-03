module "ec2" {
    source = "./modules/ec2"
    instance_type = var.instance_type
}

module "s3" {
    source = "./modules/s3"
    bucket_name = var.bucket_name
}

module "iam" {
    source = "./modules/iam"
    iam_user = var.iam_user
}