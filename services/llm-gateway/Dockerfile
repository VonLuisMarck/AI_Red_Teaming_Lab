# services/llm-gateway/Dockerfile

FROM python:3.11-slim

# Metadata
LABEL maintainer="Red Team"
LABEL description="LLM Gateway with AIDR simulation for MCP Attack Lab"

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

# Copiar código de la API
COPY api.py .

# Crear directorio para logs
RUN mkdir -p /var/log

# Exponer puerto
EXPOSE 8502

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8502/health || exit 1

# Comando de inicio
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8502", "--log-level", "info"]
