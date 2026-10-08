resource "aws_security_group" "child" {
  name        = "child"
  description = "Child security group."

  ingress {
    description = "RDP from anywhere."
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
