#!/bin/bash
# scripts/reset.sh
# Script para resetear completamente el MCP Attack Lab

set -e

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║              🗑️  MCP ATTACK LAB - RESET                             ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

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

print_warning "This will:"
echo "  • Stop all containers"
echo "  • Remove all containers"
echo "  • Remove all volumes (including Ollama models)"
echo "  • Remove all logs"
echo "  • Remove all temporary data"
echo ""

read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    print_info "Reset cancelled"
    exit 0
fi

echo ""
print_info "Starting reset process..."
echo ""

# 1. Detener y eliminar contenedores
print_info "Stopping and removing containers..."
docker-compose down -v

print_success "Containers removed"
echo ""

# 2. Eliminar logs
if [ -d "logs" ]; then
    print_info "Removing logs..."
    rm -rf logs/*
    print_success "Logs removed"
else
    print_info "No logs directory found"
fi
echo ""

# 3. Eliminar volúmenes Docker
print_info "Removing Docker volumes..."

# Obtener el nombre del proyecto (directorio actual)
PROJECT_NAME=$(basename "$(pwd)" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')

# Intentar eliminar volúmenes con diferentes nombres posibles
docker volume rm "${PROJECT_NAME}_ollama-data" 2>/dev/null || true
docker volume rm "mcp-attack-lab_ollama-data" 2>/dev/null || true
docker volume rm "ollama-data" 2>/dev/null || true

print_success "Volumes removed"
echo ""

# 4. Limpiar imágenes huérfanas (opcional)
print_info "Cleaning up unused Docker resources..."
docker system prune -f > /dev/null 2>&1

print_success "Docker cleanup complete"
echo ""

# 5. Verificar que todo está limpio
print_info "Verifying cleanup..."

if docker-compose ps | grep -q "Up"; then
    print_warning "Some containers are still running"
else
    print_success "No containers running"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║              ✅ RESET COMPLETE                                      ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

print_info "The lab has been completely reset"
echo ""
print_info "To start fresh:"
echo "  ./scripts/start.sh"
echo ""
print_warning "Note: You will need to download the LLM model again"
echo ""
