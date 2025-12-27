# services/mcp-server/server.py
"""
Servidor MCP Vulnerable para Red Teaming
Contiene vulnerabilidades intencionales para demostración educativa

⚠️ NO USAR EN PRODUCCIÓN ⚠️
"""

from fastmcp import FastMCP
import sqlite3
import subprocess
import requests
from glob import glob
import logging
from datetime import datetime

# ============================================
# Configuración de Logging
# ============================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/mcp-server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================
# Inicialización del servidor MCP
# ============================================
mcp = FastMCP("VulnerableMCP")

# ============================================
# Inicialización de Base de Datos
# ============================================
def init_database():
    """Inicializa la base de datos SQLite con datos de ejemplo"""
    logger.info("Initializing database...")
    
    conn = sqlite3.connect('/tmp/items.db')
    c = conn.cursor()
    
    # Tabla de items
    c.execute('''CREATE TABLE IF NOT EXISTS items
                 (name TEXT PRIMARY KEY, price REAL, quantity INTEGER)''')
    
    # Datos de ejemplo
    items = [
        ('banana', 1.50, 100),
        ('apple', 2.00, 150),
        ('orange', 1.75, 80),
        ('mango', 3.00, 50),
        ('grape', 4.50, 60)
    ]
    
    for item in items:
        c.execute("INSERT OR IGNORE INTO items VALUES (?, ?, ?)", item)
    
    # Tabla de secretos (para demostrar exfiltración)
    c.execute('''CREATE TABLE IF NOT EXISTS secrets
                 (id INTEGER PRIMARY KEY, api_key TEXT, password TEXT, token TEXT)''')
    
    secrets = [
        (1, 'SECRET_API_KEY_12345', 'admin_password_2024', 'jwt_token_abc123'),
        (2, 'PROD_API_KEY_67890', 'super_secret_pass', 'jwt_token_xyz789')
    ]
    
    for secret in secrets:
        c.execute("INSERT OR IGNORE INTO secrets VALUES (?, ?, ?, ?)", secret)
    
    conn.commit()
    conn.close()
    
    logger.info("Database initialized successfully")

# Inicializar DB al arrancar
init_database()

# ============================================
# RECURSOS (Resources)
# ============================================

@mcp.resource("resource://logs")
def get_logs() -> str:
    """
    Proporciona los logs del servidor MCP
    
    VULNERABILIDAD: Information Disclosure
    - Expone logs que pueden contener información sensible
    """
    logger.info("Accessing server logs")
    
    try:
        with open('/var/log/mcp-server.log', 'r') as f:
            logs = f.read()
            # Limitar a últimas 100 líneas para no saturar
            lines = logs.split('\n')
            return '\n'.join(lines[-100:])
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
        return f"Error reading logs: {str(e)}"

@mcp.resource("resource://items")
def list_items() -> str:
    """
    Lista todos los items disponibles
    
    Recurso seguro - Sin vulnerabilidades
    """
    logger.info("Listing all items")
    
    try:
        conn = sqlite3.connect('/tmp/items.db')
        c = conn.cursor()
        c.execute("SELECT name FROM items")
        items = [row[0] for row in c.fetchall()]
        conn.close()
        
        return ", ".join(items)
    except Exception as e:
        logger.error(f"Error listing items: {e}")
        return f"Error: {str(e)}"

# ============================================
# RESOURCE TEMPLATES
# ============================================

@mcp.resource("price://{item}")
def get_price(item: str) -> str:
    """
    Obtiene el precio de un item desde la base de datos
    
    VULNERABILIDAD: SQL Injection
    - No sanitiza el parámetro 'item'
    - Permite inyección SQL directa
    - Posible exfiltración de datos sensibles
    """
    logger.info(f"Getting price for item: '{item}'")
    
    try:
        conn = sqlite3.connect('/tmp/items.db')
        c = conn.cursor()
        
        # VULNERABLE: Concatenación directa sin sanitización
        query = f"SELECT price FROM items WHERE name = '{item}'"
        logger.debug(f"Executing query: {query}")
        
        c.execute(query)
        result = c.fetchone()
        conn.close()
        
        if result:
            return f"Price: ${result[0]}"
        else:
            return "Item not found"
            
    except Exception as e:
        error_msg = f"Price API Error: {str(e)}"
        logger.error(f"SQL Error for item '{item}': {e}")
        # VULNERABLE: Expone detalles del error SQL
        return error_msg

@mcp.resource("quantity://{item}")
def get_quantity(item: str) -> str:
    """
    Obtiene la cantidad de un item desde una API externa (simulada)
    
    VULNERABILIDAD: Information Disclosure
    - Expone detalles de la petición HTTP en errores
    - Revela API keys y headers en mensajes de error
    """
    logger.info(f"Getting quantity for item: '{item}'")
    
    # Simular llamada a API externa
    api_url = f"http://quantityapi.local/api/item/{item}"
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'MCP Server 1.0.0',
        'X-Api-Key': '7f1db571858da4cf0af43645812e1997'  # API Key expuesta
    }
    
    try:
        # Intentar conectar (fallará porque la API no existe)
        response = requests.get(api_url, headers=headers, timeout=2)
        
        if response.status_code == 200:
            data = response.json()
            return f"Quantity: {data.get('quantity', 'Unknown')}"
        else:
            return f"API returned status: {response.status_code}"
            
    except requests.exceptions.ConnectionError:
        # VULNERABLE: Expone detalles completos de la petición
        error_msg = f"Quantity API Error: Connection failed to '{api_url}' with headers {headers}"
        logger.error(f"Error fetching quantity for '{item}': {error_msg}")
        raise Exception(error_msg)
        
    except Exception as e:
        error_msg = f"Quantity API Error: {str(e)}"
        logger.error(f"Error fetching quantity for '{item}': {error_msg}")
        raise Exception(error_msg)

# ============================================
# TOOLS (Herramientas)
# ============================================

@mcp.tool()
def execute_server_command(command: str) -> str:
    """
    Ejecuta un comando en el servidor
    Supuestamente limitado a comandos seguros: 'date', 'whoami', 'uptime'
    
    VULNERABILIDAD: Command Injection
    - Validación débil que puede ser bypasseada
    - Permite ejecución de comandos arbitrarios
    - Usa shell=True sin sanitización
    """
    logger.info(f"Executing server command: '{command}'")
    
    # Lista blanca de comandos "seguros"
    whitelist = ['date', 'whoami', 'uptime']
    
    # VULNERABLE: Validación débil - solo verifica si contiene algún comando válido
    if not any(cmd in command for cmd in whitelist):
        logger.warning(f"Invalid command attempted: '{command}'")
        raise Exception("Invalid Command")
    
    try:
        # VULNERABLE: Usa shell=True sin sanitización
        result = subprocess.check_output(
            command,
            shell=True,  # ⚠️ PELIGROSO
            text=True,
            stderr=subprocess.STDOUT,
            timeout=5
        )
        
        logger.info(f"Command executed successfully: '{command}'")
        return result
        
    except subprocess.TimeoutExpired:
        error_msg = "Command execution timeout"
        logger.error(error_msg)
        raise Exception(error_msg)
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed: {e.output}"
        logger.error(f"Command execution error: {error_msg}")
        raise Exception(error_msg)
        
    except Exception as e:
        error_msg = f"Error executing command: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

@mcp.tool()
def fetch_price_data(url: str) -> str:
    """
    Obtiene datos de precios desde una URL externa
    
    VULNERABILIDAD: Server-Side Request Forgery (SSRF)
    - No valida ni sanitiza la URL
    - Permite acceso a recursos internos
    - Puede ser usado para port scanning
    - Puede acceder a metadata de cloud providers
    """
    logger.info(f"Fetching price data from URL: '{url}'")
    
    try:
        # VULNERABLE: No hay validación de URL
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            logger.info(f"Successfully fetched data from: '{url}'")
            return "Success"
        else:
            logger.warning(f"URL returned status {response.status_code}: '{url}'")
            return f"Failed with status: {response.status_code}"
            
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Connection failed: {str(e)}"
        logger.error(f"SSRF attempt failed for '{url}': {error_msg}")
        raise Exception(error_msg)
        
    except requests.exceptions.Timeout:
        error_msg = "Request timeout"
        logger.error(f"Timeout fetching from '{url}'")
        raise Exception(error_msg)
        
    except Exception as e:
        error_msg = f"Error fetching data: {str(e)}"
        logger.error(f"Error with URL '{url}': {error_msg}")
        raise Exception(error_msg)

@mcp.tool()
def store_file(file_content: str, file_name: str) -> str:
    """
    Almacena un archivo en el servidor
    
    Herramienta relativamente segura (para demostración de funcionalidad normal)
    """
    logger.info(f"Storing file: '{file_name}'")
    
    try:
        file_path = f"/tmp/{file_name}.mcpfile"
        
        with open(file_path, "w") as f:
            f.write(file_content)
        
        logger.info(f"File stored successfully: '{file_path}'")
        return f"File stored: {file_name}"
        
    except Exception as e:
        error_msg = f"Error storing file: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

# ============================================
# Health Check Endpoint
# ============================================

from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Crear una instancia de FastAPI para el health check
health_app = FastAPI()

@health_app.get("/health")
async def health_check():
    """Endpoint de health check para Docker"""
    return JSONResponse(
        content={
            "status": "healthy",
            "service": "mcp-server",
            "timestamp": datetime.now().isoformat()
        }
    )

# ============================================
# Iniciar Servidor
# ============================================

if __name__ == "__main__":
    logger.info("=" * 70)
    logger.info("Starting Vulnerable MCP Server")
    logger.info("⚠️  WARNING: This server contains intentional vulnerabilities")
    logger.info("⚠️  FOR EDUCATIONAL PURPOSES ONLY - DO NOT USE IN PRODUCTION")
    logger.info("=" * 70)
    
    # Registrar vulnerabilidades implementadas
    logger.info("Vulnerabilities implemented:")
    logger.info("  • SQL Injection (price://{item})")
    logger.info("  • Command Injection (execute_server_command)")
    logger.info("  • SSRF (fetch_price_data)")
    logger.info("  • Information Disclosure (logs, error messages)")
    logger.info("=" * 70)
    
    # Iniciar servidor MCP
    logger.info("Starting MCP server on port 8000...")
    
    # El servidor MCP se inicia con FastMCP
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
