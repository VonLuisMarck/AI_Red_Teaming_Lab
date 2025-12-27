#!/bin/bash
# scripts/health-check.sh
# Script para verificar el estado de todos los servicios

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║              🏥 MCP ATTACK LAB - HEALTH CHECK                       ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Función para verificar un servicio
check_service() {
    local name=$1
    local url=$2
    
    echo -n "  $name... "
    
    if curl -sf "$url" > /dev/null 2>&1; then
        print_success "Healthy"
        return 0
    else
        print_error "Unhealthy"
        return 1
    fi
}

echo "Service Health:"
check_service "MCP Server      " "http://localhost:8000/health"
check_service "LLM Gateway     " "http://localhost:8502/health"
check_service "Ollama          " "http://localhost:11434/api/tags"

echo ""
echo "Container Status:"
docker-compose ps

echo ""
echo "Resource Usage:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" \
    $(docker-compose ps -q)

echo ""
echo "Volume Usage:"
docker volume ls | grep -E "mcp-attack|ollama"

echo ""
echo "Network Status:"
docker network ls | grep mcp

echo ""
echo "Recent Logs (last 10 lines):"
echo ""
echo "=== MCP Server ==="
docker-compose logs --tail=10 mcp-server 2>/dev/null || echo "No logs available"

echo ""
echo "=== LLM Gateway ==="
docker-compose logs --tail=10 llm-gateway 2>/dev/null || echo "No logs available"

echo ""
echo "=== Ollama ==="
docker-compose logs --tail=10 ollama 2>/dev/null || echo "No logs available"

echo ""
echo "Quick Tests:"
echo ""

# Test 1: Capabilities
echo "1. Testing /capabilities endpoint..."
if curl -sf http://localhost:8502/capabilities > /dev/null 2>&1; then
    print_success "Capabilities endpoint working"
else
    print_error "Capabilities endpoint failed"
fi

# Test 2: MCP Direct
echo "2. Testing MCP direct access..."
response=$(curl -sf -X POST http://localhost:8502/mcp \
    -H "Content-Type: application/json" \
    -d '{"action":"resource","target":"resource://items"}' 2>/dev/null)

if [ -n "$response" ]; then
    print_success "MCP direct access working"
else
    print_error "MCP direct access failed"
fi

# Test 3: Ollama models
echo "3. Checking Ollama models..."
if docker exec ollama ollama list 2>/dev/null | grep -q "llama3.2"; then
    print_success "LLM model (llama3.2) available"
else
    print_warning "LLM model not found - run: docker exec ollama ollama pull llama3.2"
fi

echo ""
echo "Health check complete!"
echo ""
