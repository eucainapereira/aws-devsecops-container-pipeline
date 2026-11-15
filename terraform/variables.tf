variable "aws_region" {
  description = "Regiao da AWS onde os recursos serao provisionados"
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Nome base do projeto usado para identificacao dos recursos e repositorio ECR"
  type        = string
  default     = "aws-devsecops-container-pipeline"
}

variable "environment" {
  description = "Ambiente de implantacao"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "Bloco CIDR da VPC dedicada"
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Bloco CIDR da sub-rede publica"
  type        = string
  default     = "10.20.1.0/24"
}

variable "instance_type" {
  description = "Tipo da instancia EC2 (compativel com AWS Free Tier)"
  type        = string
  default     = "t3.micro"
}

variable "ecr_image_tag_mutability" {
  description = "Configuracao de mutabilidade das tags no ECR (MUTABLE permite atualizar a tag latest alem do commit SHA)"
  type        = string
  default     = "MUTABLE"
}
