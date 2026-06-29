
import json
import subprocess
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl

logger = logging.getLogger(__name__)

# Config SSL permissivo (para alvos com certificados inválidos)
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def make_request(url: str, timeout: int = 5, max_redirects: int = 3) -> Optional[Dict]:
    """
    HTTP GET request puro, sem dependências.
    
    Returns:
        Dict com status, headers, body, cookies ou None se falhar
    """
    try:
        req = Request(url, headers={
            "User-Agent": "Buggy/1.0 SurfaceMapper",
            "Accept": "*/*"
        })
        
        response = urlopen(req, timeout=timeout, context=SSL_CONTEXT)
        
        # Lê headers
        headers = dict(response.headers)
        
        # Lê corpo (limita a 1MB)
        body = response.read(1024 * 1024).decode("utf-8", errors="ignore")
        
        # Extrai cookies
        cookies = {}
        if "Set-Cookie" in headers:
            for cookie in headers["Set-Cookie"].split(","):
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    cookies[key.strip()] = value.split(";")[0].strip()
        
        return {
            "status": response.status,
            "headers": headers,
            "body": body,
            "cookies": cookies,
            "url": url
        }
    
    except HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": e.read().decode("utf-8", errors="ignore") if e.fp else "",
            "cookies": {},
            "url": url
        }
    except Exception as e:
        logger.debug(f"Request failed for {url}: {e}")
        return None


def run_go_binary(binary_name: str, args: List[str], timeout: int = 30) -> Dict:
    """
    Executa binário Go e retorna JSON parseado.
    
    Args:
        binary_name: Nome do binário (ex: 'tech_detector')
        args: Argumentos de linha de comando
        timeout: Timeout em segundos
    
    Returns:
        Dict com output parseado
    """
    # Encontra o binário
    module_dir = Path(__file__).parent
    binary_path = module_dir / binary_name
    
    if not binary_path.exists():
        # Tenta no PATH
        binary_path = binary_name
    
    cmd = [str(binary_path)] + args
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            logger.error(f"{binary_name} failed: {result.stderr}")
            return {"error": result.stderr}
        
        return json.loads(result.stdout)
    
    except subprocess.TimeoutExpired:
        logger.error(f"{binary_name} timeout after {timeout}s")
        return {"error": "timeout"}
    except Exception as e:
        logger.error(f"{binary_name} execution failed: {e}")
        return {"error": str(e)}


def load_json(filepath: str) -> Dict:
    """Carrega JSON de arquivo."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load {filepath}: {e}")
        return {}


def save_json(data: Dict, filepath: str):
    """Salva JSON em arquivo."""
    try:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save {filepath}: {e}")


def normalize_url(base_url: str, path: str) -> str:
    """Normaliza URL combinando base + path."""
    base = base_url.rstrip("/")
    path = path.lstrip("/")
    return f"{base}/{path}"