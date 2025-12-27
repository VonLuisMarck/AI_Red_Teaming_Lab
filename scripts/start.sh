#!/bin/bash
# scripts/start.sh
# Script para iniciar el MCP Attack Lab

set -e  # Salir si hay algún error

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║              🦅 MCP ATTACK LAB - STARTING                           ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Función para imprimir con color
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "ℹ $1"
}

# Verificar que Docker está instalado
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

print_success "Docker and Docker Compose are installed"
echo ""

# Verificar que el archivo .env existe
if [ ! -f .env ]; then
    print_warning ".env file not found"
    if [ -f .env.example ]; then
        print_info "Copying .env.example to .env"
        cp .env.example .env
        print_success ".env file created"
    else
        print_error "No .env or .env.example found"
        exit 1
    fi
fi

# Crear directorio de logs si no existe
if [ ! -d "logs" ]; then
    print_info "Creating logs directory..."
    mkdir -p logs
    print_success "Logs directory created"
fi

echo ""
print_info "Building Docker images..."
echo ""

# Build de las imágenes
docker-compose build

print_success "Docker images built successfully"
echo ""

print_info "Starting services..."
echo ""

# Iniciar servicios
docker-compose up -d

echo ""
print_info "Waiting for services to be ready..."
echo ""

# Función para verificar health de un servicio
check_health() {
    local service=$1
    local url=$2
    local max_attempts=30
    local attempt=0
    
    echo -n "  Checking $service... "
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            print_success "Ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    print_error "Timeout"
    return 1
}

# Esperar a que los servicios estén listos
sleep 10

# Health checks
check_health "MCP Server" "http://localhost:8000/health"
check_health "LLM Gateway" "http://localhost:8502/health"

# Verificar Ollama (puede tardar más)
echo -n "  Checking Ollama... "
attempt=0
max_attempts=60
while [ $attempt -lt $max_attempts ]; do
    if curl -sf "http://localhost:11434/api/tags" > /dev/null 2>&1; then
        print_success "Ready"
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    print_warning "Ollama may still be starting"
fi

echo ""
print_info "Downloading LLM model (this may take a few minutes)..."
echo ""

# Descargar modelo LLM
if docker exec ollama ollama list | grep -q "llama3.2"; then
    print_success "Model llama3.2 already downloaded"
else
    print_info "Downloading llama3.2 model..."
    docker exec ollama ollama pull llama3.2
    print_success "Model downloaded successfully"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║              ✅ MCP ATTACK LAB IS READY!                            ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

print_info "Service URLs:"
echo "  • API Gateway:       http://localhost:8502"
echo "  • API Docs (Swagger): http://localhost:8502/docs"
echo "  • MCP Server:        http://localhost:8000"
echo "  • Ollama API:        http://localhost:11434"
echo ""

print_info "Quick Test:"
echo "  curl http://localhost:8502/health"
echo "  curl http://localhost:8502/capabilities"
echo ""

print_info "Documentation:"
echo "  • Integration Guide: ./INTEGRATION.md"
echo "  • Examples:          ./examples/"
echo ""

print_info "View Logs:"
echo "  • All services:      docker-compose logs -f"
echo "  • Gateway only:      docker-compose logs -f llm-gateway"
echo "  • MCP Server only:   docker-compose logs -f mcp-server"
echo "  • Log files:         tail -f logs/gateway.log"
echo ""

print_info "Management:"
echo "  • Stop:              ./scripts/stop.sh"
echo "  • Restart:           docker-compose restart [service]"
echo "  • Reset:             ./scripts/reset.sh"
echo ""

print_success "Ready for Red Teaming! 🎯"
echo ""
