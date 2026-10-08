resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.web.id
  cidr_ipv6         = "::/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-secure-logs"
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id
  acl    = "private"
}

resource "aws_db_instance" "main" {
  identifier          = "main"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = var.db_password
  publicly_accessible = false
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length = var.password_length
}

resource "aws_iam_role" "reader" {
  name = "reader"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "reader" {
  name = "reader"
  role = aws_iam_role.reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "${aws_s3_bucket.logs.arn}/*"
    }]
  })
}

data "aws_iam_policy_document" "guard" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.logs.arn}/*"]
  }

  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "guard" {
  name   = "guard"
  policy = data.aws_iam_policy_document.guard.json
}
