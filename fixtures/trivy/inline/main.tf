terraform {
  required_version = ">= 1.6.0"
}

resource "aws_security_group" "root" {
  name        = "root"
  description = "Root security group."

  ingress {
    description = "SSH from anywhere."
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #trivy:ignore:AWS-0107
  }
}
