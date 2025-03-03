resource "aws_iam_user" "vulnerable_user" {
    name = var.iam_user
}

resource "aws_iam_user_policy_attachment" "admin_policy" {
    user = aws_iam_user.vulnerable_user.name
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "iam_user_name" {
    value = aws_iam_user.vulnerable_user.name
}