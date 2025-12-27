# services/llm-gateway/api.py
"""
LLM Gateway API con simulación de Falcon AIDR
Proporciona endpoints REST para integración con frameworks de ataque

Este gateway:
1. Conecta con Ollama (LLM local)
2. Conecta con el servidor MCP vulnerable
3. Simula detección de Falcon AIDR
4. Proporciona API REST para frameworks de ataque
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import asyncio
from datetime import datetime
import logging
import os
import re

# Imports para LLM y MCP
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    logging.warning("Ollama not available - LLM features will be limited")

from fastmcp import Client

# ============================================
# Configuración de Logging
# ============================================
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================
# Configuración
# ============================================
OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://ollama:11434')
MCP_SERVER_URL = os.getenv('MCP_SERVER_URL', 'http://mcp-server:8000/mcp/')
AIDR_ENABLED = os.getenv('AIDR_ENABLED', 'true').lower() == 'true'
AIDR_MODE = os.getenv('AIDR_MODE', 'monitor')  # monitor, block, disabled

logger.info(f"Configuration:")
logger.info(f"  OLLAMA_HOST: {OLLAMA_HOST}")
logger.info(f"  MCP_SERVER_URL: {MCP_SERVER_URL}")
logger.info(f"  AIDR_ENABLED: {AIDR_ENABLED}")
logger.info(f"  AIDR_MODE: {AIDR_MODE}")

# ============================================
# FastAPI App
# ============================================
app = FastAPI(
    title="MCP Attack Lab API",
    description="API Gateway para testing de seguridad en MCP con simulación de Falcon AIDR",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cliente MCP global
mcp_client = Client(MCP_SERVER_URL)

# ============================================
# Falcon AIDR Simulator
# ============================================

class FalconAIDRSimulator:
    """
    Simula la detección de Falcon AIDR
    Analiza prompts y payloads en busca de patrones maliciosos
    """
    
    # Patrones maliciosos para detección
    MALICIOUS_PATTERNS = {
        'prompt_injection': [
            r'ignore\s+(all\s+)?(previous|prior)\s+instructions',
            r'disregard\s+(all\s+)?(previous|prior)',
            r'forget\s+(everything|all)',
            r'new\s+instructions?:',
            r'you\s+are\s+now',
            r'pretend\s+(you\s+are|to\s+be)',
        ],
        'jailbreak': [
            r'DAN\s+mode',
            r'developer\s+mode',
            r'unrestricted\s+(AI|mode)',
            r'without\s+(any\s+)?(restrictions|limits|rules)',
            r'bypass\s+(safety|security|filters)',
        ],
        'sql_injection': [
            r"'\s*OR\s+'1'\s*=\s*'1",
            r"'\s*OR\s+1\s*=\s*1",
            r'UNION\s+SELECT',
            r'DROP\s+TABLE',
            r"';\s*--",
            r"'\s*--",
            r'UNION\s+ALL\s+SELECT',
        ],
        'command_injection': [
            r';\s*id\s*$',
            r';\s*whoami',
            r'&&\s*id',
            r'\|\s*whoami',
            r'\$\(cat\s+',
            r'`cat\s+',
            r';\s*cat\s+/etc/passwd',
        ],
        'ssrf': [
            r'169\.254\.169\.254',
            r'metadata\.google\.internal',
            r'localhost:\d+',
            r'127\.0\.0\.1:\d+',
            r'file://',
            r'0\.0\.0\.0',
        ],
        'data_exfiltration': [
            r'show\s+me\s+all',
            r'dump\s+(database|table)',
            r'list\s+all\s+(users|passwords|credentials)',
            r'get\s+(all\s+)?(credentials|passwords|secrets)',
            r'export\s+all',
        ]
    }
    
    # Puntajes de riesgo por tipo de amenaza
    RISK_SCORES = {
        'prompt_injection': 40,
        'jailbreak': 60,
        'sql_injection': 70,
        'command_injection': 70,
        'ssrf': 50,
        'data_exfiltration': 30,
        'llm_manipulation': 30,
        'sensitive_data_request': 20
    }
    
    def __init__(self):
        self.alerts = []
        self.blocked_prompts = []
        logger.info("Falcon AIDR Simulator initialized")
    
    def analyze(self, text: str, user_id: str = "anonymous") -> Dict[str, Any]:
        """
        Analiza un texto en busca de patrones maliciosos
        
        Returns:
            Dict con análisis de riesgo y amenazas detectadas
        """
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "text": text[:200],  # Primeros 200 caracteres
            "risk_score": 0,
            "threats_detected": [],
            "action": "allow",
            "details": []
        }
        
        text_lower = text.lower()
        
        # Detectar patrones maliciosos
        for threat_type, patterns in self.MALICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    severity = self._get_severity(threat_type)
                    analysis["threats_detected"].append({
                        "type": threat_type,
                        "pattern": pattern,
                        "severity": severity
                    })
                    analysis["risk_score"] += self.RISK_SCORES.get(threat_type, 10)
                    
                    logger.warning(
                        f"AIDR Detection: {threat_type} | "
                        f"Pattern: {pattern} | "
                        f"User: {user_id}"
                    )
        
        # Detectar manipulación del LLM
        manipulation_keywords = [
            'ignore', 'disregard', 'forget', 'override',
            'bypass', 'disable', 'turn off', 'deactivate'
        ]
        
        manipulation_count = sum(
            1 for keyword in manipulation_keywords 
            if keyword in text_lower
        )
        
        if manipulation_count >= 2:
            analysis["threats_detected"].append({
                "type": "llm_manipulation",
                "pattern": "multiple_manipulation_keywords",
                "severity": "high"
            })
            analysis["risk_score"] += 30
        
        # Detectar solicitudes de información sensible
        sensitive_keywords = [
            'password', 'credential', 'api key', 'secret',
            'token', 'private key', 'database', 'admin'
        ]
        
        sensitive_count = sum(
            1 for keyword in sensitive_keywords 
            if keyword in text_lower
        )
        
        if sensitive_count >= 2:
            analysis["threats_detected"].append({
                "type": "sensitive_data_request",
                "pattern": "multiple_sensitive_keywords",
                "severity": "medium"
            })
            analysis["risk_score"] += 20
        
        # Determinar acción basada en risk score y modo AIDR
        if AIDR_MODE == 'disabled':
            analysis["action"] = "allow"
            analysis["details"].append("AIDR disabled - all requests allowed")
        elif analysis["risk_score"] >= 70:
            if AIDR_MODE == 'block':
                analysis["action"] = "block"
                analysis["details"].append("BLOCKED: Critical risk score detected")
                self.blocked_prompts.append(analysis)
            else:
                analysis["action"] = "warn"
                analysis["details"].append("WARNING: Critical risk detected (monitor mode)")
        elif analysis["risk_score"] >= 50:
            if AIDR_MODE == 'block':
                analysis["action"] = "block"
                analysis["details"].append("BLOCKED: High risk score detected")
                self.blocked_prompts.append(analysis)
            else:
                analysis["action"] = "warn"
                analysis["details"].append("WARNING: High risk detected")
        elif analysis["risk_score"] >= 30:
            analysis["action"] = "warn"
            analysis["details"].append("WARNING: Suspicious activity detected")
        else:
            analysis["action"] = "allow"
            analysis["details"].append("ALLOWED: No significant threats detected")
        
        # Registrar alerta si hay amenazas
        if analysis["threats_detected"]:
            self.alerts.append(analysis)
            logger.info(
                f"AIDR Alert: Risk={analysis['risk_score']} | "
                f"Action={analysis['action']} | "
                f"Threats={len(analysis['threats_detected'])}"
            )
        
        return analysis
    
    def _get_severity(self, threat_type: str) -> str:
        """Obtiene la severidad de una amenaza"""
        severity_map = {
            'prompt_injection': 'high',
            'jailbreak': 'critical',
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'ssrf': 'high',
            'data_exfiltration': 'medium',
            'llm_manipulation': 'high',
            'sensitive_data_request': 'medium'
        }
        return severity_map.get(threat_type, 'low')
    
    def get_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas de monitoreo"""
        threat_counts = {}
        for alert in self.alerts:
            for threat in alert["threats_detected"]:
                threat_type = threat["type"]
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        avg_risk = 0.0
        if self.alerts:
            total_risk = sum(alert["risk_score"] for alert in self.alerts)
            avg_risk = round(total_risk / len(self.alerts), 2)
        
        return {
            "total_alerts": len(self.alerts),
            "blocked_prompts": len(self.blocked_prompts),
            "threat_types": threat_counts,
            "average_risk_score": avg_risk
        }

# Instancia global de AIDR
aidr = FalconAIDRSimulator()

# ============================================
# Modelos de Datos (Pydantic)
# ============================================

class PromptRequest(BaseModel):
    prompt: str
    model: Optional[str] = "llama3.2"
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 2048

class MCPRequest(BaseModel):
    action: str  # "resource" o "tool"
    target: str  # URI del resource o nombre del tool
    params: Optional[Dict[str, Any]] = {}

class HealthResponse(BaseModel):
    status: str
    timestamp: str

# ============================================
# Endpoints - Health & Info
# ============================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def root():
    """Información básica de la API"""
    return {
        "name": "MCP Attack Lab API",
        "version": "1.0.0",
        "description": "API Gateway para Red Teaming de MCP con simulación de Falcon AIDR",
        "endpoints": {
            "health": "GET /health - Health check",
            "capabilities": "GET /capabilities - Listar capacidades MCP",
            "prompt": "POST /prompt - Enviar prompt al LLM",
            "mcp": "POST /mcp - Acceso directo a MCP",
            "batch": "POST /batch - Múltiples requests en batch",
            "docs": "GET /docs - Documentación interactiva"
        },
        "aidr": {
            "enabled": AIDR_ENABLED,
            "mode": AIDR_MODE
        }
    }

# ============================================
# Endpoints - MCP Capabilities
# ============================================

@app.get("/capabilities")
async def get_capabilities():
    """
    Lista todas las capacidades del servidor MCP
    Útil para reconocimiento inicial
    """
    logger.info("Listing MCP capabilities")
    
    try:
        async with mcp_client:
            resources = await mcp_client.list_resources()
            templates = await mcp_client.list_resource_templates()
            tools = await mcp_client.list_tools()
        
        capabilities = {
            "status": "success",
            "resources": [
                {
                    "name": r.name,
                    "uri": str(r.uri),
                    "description": r.description
                }
                for r in resources
            ],
            "templates": [
                {
                    "name": t.name,
                    "template": t.uriTemplate,
                    "description": t.description
                }
                for t in templates
            ],
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "params": list(t.inputSchema.get('properties', {}).keys())
                }
                for t in tools
            ],
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(
            f"Capabilities listed: "
            f"{len(capabilities['resources'])} resources, "
            f"{len(capabilities['templates'])} templates, "
            f"{len(capabilities['tools'])} tools"
        )
        
        return capabilities
        
    except Exception as e:
        logger.error(f"Error getting capabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# Endpoints - Direct MCP Access
# ============================================

@app.post("/mcp")
async def mcp_direct(request: MCPRequest):
    """
    Acceso directo al servidor MCP (sin pasar por el LLM)
    
    Útil para testing directo de vulnerabilidades MCP
    
    Ejemplos:
    
    Resource:
    {
        "action": "resource",
        "target": "price://banana"
    }
    
    Tool:
    {
        "action": "tool",
        "target": "execute_server_command",
        "params": {"command": "date"}
    }
    """
    logger.info(f"MCP direct access: {request.action} - {request.target}")
    
    # Analizar con AIDR si está habilitado
    if AIDR_ENABLED:
        # Construir texto para análisis
        analysis_text = f"{request.action} {request.target}"
        if request.params:
            analysis_text += f" {str(request.params)}"
        
        aidr_analysis = aidr.analyze(analysis_text, user_id="mcp_direct")
        
        # Bloquear si AIDR lo determina
        if aidr_analysis["action"] == "block":
            logger.warning(
                f"AIDR blocked MCP request: {request.action} - {request.target}"
            )
            return {
                "status": "blocked",
                "aidr_analysis": aidr_analysis,
                "message": "Request blocked by Falcon AIDR",
                "timestamp": datetime.now().isoformat()
            }
    
    try:
        async with mcp_client:
            if request.action == "resource":
                result = await mcp_client.read_resource(request.target)
                data = result[0].text if result else None
                
            elif request.action == "tool":
                result = await mcp_client.call_tool(request.target, request.params)
                data = result[0].text if result else None
                
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid action. Use 'resource' or 'tool'"
                )
        
        logger.info(f"MCP request successful: {request.action} - {request.target}")
        
        response = {
            "status": "success",
            "result": data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Incluir análisis AIDR si está habilitado
        if AIDR_ENABLED:
            response["aidr_analysis"] = aidr_analysis
        
        return response
        
    except Exception as e:
        logger.error(f"MCP error: {e}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# ============================================
# Endpoints - LLM Prompt
# ============================================

@app.post("/prompt")
async def send_prompt(request: PromptRequest):
    """
    Envía un prompt al LLM que puede usar MCP
    
    El LLM tiene acceso a las capacidades MCP y puede decidir usarlas
    
    Ejemplo:
    {
        "prompt": "What is the price of bananas?",
        "model": "llama3.2"
    }
    """
    logger.info(f"Prompt received: {request.prompt[:100]}...")
    
    # Analizar con AIDR
    if AIDR_ENABLED:
        aidr_analysis = aidr.analyze(request.prompt, user_id="llm_user")
        
        # Bloquear si AIDR lo determina
        if aidr_analysis["action"] == "block":
            logger.warning(f"AIDR blocked prompt: {request.prompt[:50]}...")
            return {
                "status": "blocked",
                "aidr_analysis": aidr_analysis,
                "response": (
                    "🛡️ **FALCON AIDR BLOCKED THIS REQUEST**\n\n"
                    f"This prompt has been blocked due to security concerns.\n\n"
                    f"**Risk Score:** {aidr_analysis['risk_score']}\n"
                    f"**Threats Detected:** {len(aidr_analysis['threats_detected'])}\n\n"
                    "Please rephrase your request without malicious patterns."
                ),
                "timestamp": datetime.now().isoformat()
            }
    
    # Verificar si Ollama está disponible
    if not OLLAMA_AVAILABLE:
        logger.warning("Ollama not available - returning mock response")
        return {
            "status": "success",
            "response": "LLM not available - this is a mock response",
            "mcp_used": False,
            "aidr_analysis": aidr_analysis if AIDR_ENABLED else None,
            "timestamp": datetime.now().isoformat()
        }
    
    try:
        # Obtener capacidades MCP
        async with mcp_client:
            resources = await mcp_client.list_resources()
            templates = await mcp_client.list_resource_templates()
            tools = await mcp_client.list_tools()
        
        # Construir system prompt con capacidades MCP
        system_prompt = f"""You are an AI assistant with access to MCP capabilities.

Available Resources: {[r.name for r in resources]}
Available Templates: {[t.uriTemplate for t in templates]}
Available Tools: {[t.name for t in tools]}

When the user asks for information, you can use the appropriate MCP capability.
Respond naturally and helpfully."""
        
        # Llamar al LLM
        response = ollama.chat(
            model=request.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": request.prompt}
            ],
            options={
                "temperature": request.temperature,
                "num_predict": request.max_tokens
            }
        )
        
        llm_response = response['message']['content']
        logger.info(f"LLM response generated: {llm_response[:100]}...")
        
        result = {
            "status": "success",
            "response": llm_response,
            "mcp_used": False,  # Simplificado - no parseamos uso de MCP
            "timestamp": datetime.now().isoformat()
        }
        
        # Incluir análisis AIDR
        if AIDR_ENABLED:
            result["aidr_analysis"] = aidr_analysis
        
        return result
        
    except Exception as e:
        logger.error(f"Error processing prompt: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# Endpoints - Batch Processing
# ============================================

@app.post("/batch")
async def batch_requests(requests: List[MCPRequest]):
    """
    Procesa múltiples requests MCP en batch
    
    Útil para testing automatizado de múltiples payloads
    
    Ejemplo:
    [
        {"action": "resource", "target": "price://banana"},
        {"action": "resource", "target": "price://apple"},
        {"action": "tool", "target": "execute_server_command", "params": {"command": "date"}}
    ]
    """
    logger.info(f"Batch request: {len(requests)} items")
    
    results = []
    
    for req in requests:
        try:
            # Analizar con AIDR
            if AIDR_ENABLED:
                analysis_text = f"{req.action} {req.target}"
                if req.params:
                    analysis_text += f" {str(req.params)}"
                
                aidr_analysis = aidr.analyze(analysis_text, user_id="batch_user")
                
                # Si está bloqueado, añadir resultado y continuar
                if aidr_analysis["action"] == "block":
                    results.append({
                        "request": req.dict(),
                        "status": "blocked",
                        "aidr_analysis": aidr_analysis
                    })
                    continue
            
            # Ejecutar request MCP
            async with mcp_client:
                if req.action == "resource":
                    result = await mcp_client.read_resource(req.target)
                    data = result[0].text if result else None
                elif req.action == "tool":
                    result = await mcp_client.call_tool(req.target, req.params)
                    data = result[0].text if result else None
                else:
                    data = None
            
            result_dict = {
                "request": req.dict(),
                "status": "success",
                "result": data
            }
            
            if AIDR_ENABLED:
                result_dict["aidr_analysis"] = aidr_analysis
            
            results.append(result_dict)
            
        except Exception as e:
            results.append({
                "request": req.dict(),
                "status": "error",
                "error": str(e)
            })
    
    return {
        "status": "success",
        "total": len(requests),
        "results": results,
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# Endpoints - AIDR Statistics
# ============================================

@app.get("/aidr/statistics")
async def get_aidr_statistics():
    """
    Obtiene estadísticas del monitor AIDR
    """
    if not AIDR_ENABLED:
        return {
            "status": "disabled",
            "message": "AIDR is disabled",
            "timestamp": datetime.now().isoformat()
        }
    
    try:
        stats = aidr.get_statistics()
        
        return {
            "status": "success",
            "statistics": stats,
            "recent_alerts": aidr.alerts[-10:],  # Últimas 10 alertas
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/aidr/alerts")
async def get_aidr_alerts(limit: int = 50):
    """
    Obtiene las alertas recientes de AIDR
    """
    if not AIDR_ENABLED:
        return {
            "status": "disabled",
            "message": "AIDR is disabled",
            "timestamp": datetime.now().isoformat()
        }
    
    try:
        alerts = aidr.alerts[-limit:]
        
        return {
            "status": "success",
            "count": len(alerts),
            "alerts": alerts,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# Startup Event
# ============================================

@app.on_event("startup")
async def startup_event():
    """Inicialización al arrancar"""
    logger.info("=" * 70)
    logger.info("Starting LLM Gateway API")
    logger.info("=" * 70)
    logger.info(f"Ollama Host: {OLLAMA_HOST}")
    logger.info(f"MCP Server: {MCP_SERVER_URL}")
    logger.info(f"AIDR Enabled: {AIDR_ENABLED}")
    logger.info(f"AIDR Mode: {AIDR_MODE}")
    logger.info("=" * 70)
    logger.info("API Documentation available at /docs")
    logger.info("=" * 70)

@app.on_event("shutdown")
async def shutdown_event():
    """Limpieza al cerrar"""
    logger.info("Shutting down LLM Gateway API...")
