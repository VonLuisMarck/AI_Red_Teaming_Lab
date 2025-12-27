# services/mcp-server/Dockerfile

FROM python:3.11-slim

# Metadata
LABEL maintainer="CrowdStrike Red Team"
LABEL description="Vulnerable MCP Server for Red Teaming demos"

# Instalar curl para health checks
RUN apt-get update && \
    apt-get install -y curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Directorio de trabajo
WORKDIR /app

# Copiar requirements primero (para cache de Docker)
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código del servidor
COPY server.py .

# Crear directorio para logs
RUN mkdir -p /var/log

# Exponer puerto
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Comando de inicio
CMD ["python", "server.py"]
