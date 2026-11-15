# =============================================================================
# 1. REDE E SEGURANCA (VPC Dedicada + Security Group Zero-SSH)
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Hardening: bloqueia todo trafego no Default Security Group da VPC (CIS AWS Benchmark)
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-default-sg-restricted"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Sub-rede com map_public_ip_on_launch = false (Boa pratica Trivy AVD-AWS-0164).
# O IP publico e associado explicitamente via Elastic IP na instancia EC2.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Group restritivo:
# - NENHUMA porta 22 (SSH) aberta.
# - Entrada exclusiva na porta 80 (HTTP) para acesso a aplicacao web.
# - Saida restrita a HTTPS (443) para comunicacao com AWS SSM, Amazon ECR e repositorios AL2023.
resource "aws_security_group" "ec2_sg" {
  name        = "${var.project_name}-ec2-sg"
  description = "Security Group restritivo para o container web (HTTP 80 in, HTTPS 443 out, Zero SSH)"
  vpc_id      = aws_vpc.main.id

  # trivy:ignore:AVD-AWS-0107 Entrada publica na porta 80 necessaria para o servidor web publico e scan DAST
  ingress {
    description = "Permite trafego HTTP publico para a aplicacao web"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    # trivy:ignore:AVD-AWS-0107
    cidr_blocks = ["0.0.0.0/0"]
  }

  # trivy:ignore:AVD-AWS-0104 Saida HTTPS publica necessaria para AWS SSM Agent, pull do ECR e patches dnf
  egress {
    description = "Permite saida HTTPS para AWS SSM, Amazon ECR e atualizacoes de pacotes"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    # trivy:ignore:AVD-AWS-0104
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-ec2-sg"
  }
}

# =============================================================================
# 2. ACESSO E GESTAO (IAM Role para AWS SSM + Leitura no Amazon ECR)
# =============================================================================

resource "aws_iam_role" "ec2_ssm_ecr_role" {
  name        = "${var.project_name}-ec2-role"
  description = "IAM Role para gerenciamento sem SSH via AWS SSM e pull de imagens no Amazon ECR"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Politica gerenciada oficial da AWS para operacao do Systems Manager (SSM)
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm_ecr_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Politica customizada de privilegio minimo para leitura no repositorio ECR do projeto
# trivy:ignore:AVD-AWS-0057 ecr:GetAuthorizationToken exige Resource '*' pela especificacao da API AWS
resource "aws_iam_role_policy" "ecr_read_only" {
  name = "${var.project_name}-ecr-pull-policy"
  role = aws_iam_role.ec2_ssm_ecr_role.id

  # trivy:ignore:AVD-AWS-0057
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowECRAuthorizationToken"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "AllowPullFromProjectRepository"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = aws_ecr_repository.app.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.project_name}-instance-profile"
  role = aws_iam_role.ec2_ssm_ecr_role.name
}

# =============================================================================
# 3. REGISTRY DE CONTAINERS (Amazon ECR + Scan on Push + Lifecycle Policy)
# =============================================================================

# trivy:ignore:AVD-AWS-0031 Configuravel via var.ecr_image_tag_mutability para suportar rolling tag 'latest' e commit SHA
# trivy:ignore:AVD-AWS-0033 Utiliza criptografia AES256 nativa para manter conformidade com o AWS Free Tier sem custo de CMK
resource "aws_ecr_repository" "app" {
  name = var.project_name
  # trivy:ignore:AVD-AWS-0031
  image_tag_mutability = var.ecr_image_tag_mutability
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  # trivy:ignore:AVD-AWS-0033
  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name = "${var.project_name}-ecr"
  }
}

# Lifecycle Policy: mantem apenas as ultimas 3 imagens para evitar custos e preservar o Free Tier
resource "aws_ecr_lifecycle_policy" "keep_last_3" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Mantem apenas as ultimas 3 imagens no ECR para controle de custos (Free Tier)"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 3
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# =============================================================================
# 4. COMPUTACAO (Instancia EC2 Amazon Linux 2023 + EBS Criptografado + IMDSv2)
# =============================================================================

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  monitoring             = true
  ebs_optimized          = true

  # Hardening: Exige IMDSv2 (session-oriented tokens) e limita hop_limit = 1
  # impedindo que containers consigam acessar metadados da instancia em caso de SSRF
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Hardening: Volume raiz EBS criptografado em repouso
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  # Garante quebras de linha LF (Unix) mesmo quando executado a partir de hosts Windows
  user_data                   = replace(file("${path.module}/user_data.sh"), "\r\n", "\n")
  user_data_replace_on_change = true

  tags = {
    Name = "${var.project_name}-ec2"
  }
}

# Elastic IP associado a instancia EC2 (garante IP fixo e evita auto-assign na subnet)
resource "aws_eip" "app_eip" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-eip"
  }
}

resource "aws_eip_association" "app_eip_assoc" {
  instance_id   = aws_instance.app.id
  allocation_id = aws_eip.app_eip.id
}
