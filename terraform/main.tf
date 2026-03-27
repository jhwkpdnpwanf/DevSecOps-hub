data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "reports" {
  bucket = "${var.project_name}-${data.aws_caller_identity.current.account_id}-reports"
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "archive-old-reports"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "GLACIER"
    }
  }
}

# Runtime app role that can read/list reports (and write if needed)
resource "aws_iam_role" "app_runtime" {
  name = "${var.project_name}-app-runtime-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "sts:AssumeRole",
        Principal = {
          AWS = length(var.app_role_principal_arns) > 0 ? var.app_role_principal_arns : ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
        }
      }
    ]
  })
}

resource "aws_iam_policy" "app_s3_policy" {
  name = "${var.project_name}-app-s3-policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "ListBucket",
        Effect = "Allow",
        Action = ["s3:ListBucket"],
        Resource = [aws_s3_bucket.reports.arn]
      },
      {
        Sid    = "ReadWriteReports",
        Effect = "Allow",
        Action = ["s3:GetObject", "s3:PutObject", "s3:GetObjectVersion"],
        Resource = ["${aws_s3_bucket.reports.arn}/*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_s3_attach" {
  role       = aws_iam_role.app_runtime.name
  policy_arn = aws_iam_policy.app_s3_policy.arn
}

# GitHub Actions OIDC for CI upload/read
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_actions" {
  name = "${var.project_name}-github-actions-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          },
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "github_actions_s3" {
  name = "${var.project_name}-github-actions-s3-policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "ListBucket",
        Effect = "Allow",
        Action = ["s3:ListBucket"],
        Resource = [aws_s3_bucket.reports.arn]
      },
      {
        Sid    = "PutAndGetReports",
        Effect = "Allow",
        Action = ["s3:GetObject", "s3:PutObject"],
        Resource = ["${aws_s3_bucket.reports.arn}/*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "github_actions_attach" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions_s3.arn
}

resource "aws_db_subnet_group" "hub_mysql" {
  name       = "${var.project_name}-mysql-subnet-group"
  subnet_ids = var.db_subnet_ids

  tags = {
    Name = "${var.project_name}-mysql-subnet-group"
  }
}

resource "aws_security_group" "hub_mysql" {
  name        = "${var.project_name}-mysql-sg"
  description = "Security group for DevSecOps Hub RDS MySQL"
  vpc_id      = var.vpc_id

  ingress {
    description = "MySQL access"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = var.db_allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-mysql-sg"
  }
}

resource "aws_db_instance" "hub_mysql" {
  identifier                  = "${var.project_name}-mysql"
  engine                      = "mysql"
  engine_version              = var.db_engine_version
  instance_class              = var.db_instance_class
  allocated_storage           = var.db_allocated_storage
  db_name                     = var.db_name
  username                    = var.db_username
  password                    = var.db_password
  port                        = 3306
  db_subnet_group_name        = aws_db_subnet_group.hub_mysql.name
  vpc_security_group_ids      = [aws_security_group.hub_mysql.id]
  publicly_accessible         = var.db_publicly_accessible
  multi_az                    = var.db_multi_az
  storage_encrypted           = true
  backup_retention_period     = var.db_backup_retention_period
  deletion_protection         = var.db_deletion_protection
  skip_final_snapshot         = true
  auto_minor_version_upgrade  = true
  apply_immediately           = true
  performance_insights_enabled = false

  tags = {
    Name = "${var.project_name}-mysql"
  }
}