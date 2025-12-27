#!/bin/bash
# scripts/stop.sh
# Script para detener el MCP Attack Lab

set -e

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║              🛑 MCP ATTACK LAB - STOPPING                           ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "ℹ $1"
}

print_info "Stopping services..."
echo ""

# Detener servicios
docker-compose down

echo ""
print_success "All services stopped"
echo ""

print_info "Container status:"
docker-compose ps

echo ""
print_info "To start again: ./scripts/start.sh"
print_info "To reset everything: ./scripts/reset.sh"
echo ""
