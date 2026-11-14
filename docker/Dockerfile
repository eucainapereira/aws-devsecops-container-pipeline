# Imagem base oficial Nginx em Alpine Linux com versao pinada (CIS Docker Benchmark)
FROM nginx:1.27.4-alpine3.21

LABEL maintainer="DevSecOps Portfolio Engineering" \
      description="Hardened Non-Root Nginx Alpine Container" \
      org.opencontainers.image.source="https://github.com/eucainapereira/aws-devsecops-container-pipeline"

# Atualiza pacotes do sistema operacional para aplicar patches de seguranca recentes
# e ajusta permissoes de diretorios para execucao com usuario nao-root (nginx)
RUN apk update && \
    apk upgrade --no-cache && \
    rm -rf /etc/nginx/conf.d/default.conf /usr/share/nginx/html/* /var/cache/apk/* && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx \
        /var/cache/nginx \
        /var/run \
        /var/run/nginx.pid \
        /var/log/nginx \
        /usr/share/nginx/html \
        /etc/nginx

# Copia configuracao hardened do Nginx e arquivos estaticos da aplicacao
COPY --chown=nginx:nginx docker/nginx.conf /etc/nginx/nginx.conf
COPY --chown=nginx:nginx app/ /usr/share/nginx/html/

# Porta nao-privilegiada (>1024) para permitir execucao sem root
EXPOSE 8080

# Altera contexto de execucao para usuario nao-root
USER nginx

# Healthcheck nativo validando o processo na porta 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
