resource "aws_security_group" "insecure_sg" {
    name = "insecure_sg"
    description = "Allow SSH access from anywhere"

    ingress {
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"] # allowing SSH access from anywhere
    }

    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
}

resource "aws_instance" "vulnerable_instance" {
    ami = "ami-0c55b159cbfafe1f0"
    instance_type = var.instance_type
    security_groups = [aws_security_group.insecure_sg.name]

    tags = {
      Name = "VulnerableEC2"
    }
}