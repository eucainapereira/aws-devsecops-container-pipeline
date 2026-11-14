#!/bin/bash
set -euxo pipefail

# Redireciona logs do user_data para auditoria em /var/log/user-data.log
exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

echo "[INFO] Aguardando conectividade de rede (associacao do Elastic IP)..."
for i in {1..30}; do
  if curl -sI --connect-timeout 3 https://aws.amazon.com >/dev/null 2>&1; then
    echo "[INFO] Conectividade HTTPS confirmada."
    break
  fi
  sleep 2
done

echo "[INFO] Iniciando bootstrap seguro da instancia Amazon Linux 2023..."

# Atualiza pacotes do sistema operacional
dnf update -y

# Instala Docker Engine
dnf install -y docker

# Habilita e inicia o servico do Docker
systemctl enable --now docker
usermod -aG docker ec2-user

# Garante que o agente do AWS Systems Manager (SSM) esta ativo para deploy sem SSH
systemctl enable --now amazon-ssm-agent

echo "[INFO] Bootstrap concluido com sucesso. Docker e SSM Agent operacionais."
