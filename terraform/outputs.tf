output "ec2_public_ip" {
  description = "Endereco IP publico da instancia EC2 onde a aplicacao esta publicada"
  value       = aws_instance.app.public_ip
}

output "ecr_repository_url" {
  description = "URL completa do repositorio privado no Amazon ECR"
  value       = aws_ecr_repository.app.repository_url
}

output "ec2_instance_id" {
  description = "ID da instancia EC2 gerenciada via AWS Systems Manager (SSM)"
  value       = aws_instance.app.id
}

output "application_url" {
  description = "URL HTTP da aplicacao em execucao"
  value       = "http://${aws_instance.app.public_ip}"
}
