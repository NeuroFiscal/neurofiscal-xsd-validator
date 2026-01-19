
# app.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from io import BytesIO
from urllib.parse import urlparse
import re

import httpx
from lxml import etree

# -----------------------------------------------------------------------------
# Configurações gerais
# -----------------------------------------------------------------------------
APP_NAME = "NeuroFiscal XSD Validator"
APP_VERSION = "1.2.0"

# Limites (ajuste se necessário)
MAX_XML_BYTES = 2_000_000      # 2 MB
MAX_XSD_BYTES = 2_000_000      # 2 MB

# Timeouts: (connect, read) em segundos
HTTP_TIMEOUT = (5.0, 20.0)

# (Opcional) Lista branca de hosts para o xsdUrl.
# Coloque None para permitir qualquer host público.
ALLOWED_XSD_HOSTS: Optional[set[str]] = None
# Exemplo para travar em hosts específicos:
# ALLOWED_XSD_HOSTS = {"raw.githubusercontent.com", "cdn.jsdelivr.net", "neurofiscal.github.io"}

# Headers usados ao baixar XSD (raiz e includes/imports)
DEFAULT_FETCH_HEADERS = {
    "User-Agent": f"{APP_NAME}/{APP_VERSION} (+https://example.com)",
    "Accept": "application/xml,text/xml,application/octet-stream,*/*;q=0.8",
}

# -----------------------------------------------------------------------------
# FastAPI
# -----------------------------------------------------------------------------
app = FastAPI(title=APP_NAME, version=APP_VERSION)

# (Opcional) CORS liberado — ajuste conforme sua política
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------
class ValidatePayload(BaseModel):
    xml: str
    xsdUrl: HttpUrl


# -----------------------------------------------------------------------------
# Utilitários e funções de suporte
# -----------------------------------------------------------------------------
def is_host_allowed(url: str) -> bool:
    """Valida se o host do xsdUrl é permitido (se ALLOWED_XSD_HOSTS estiver configurado)."""
    if ALLOWED_XSD_HOSTS is None:
        return True
    host = (urlparse(url).hostname or "").lower()
    return host in ALLOWED_XSD_HOSTS


def raw_github_to_jsdelivr(url: str) -> Optional[str]:
    """
    Converte uma URL de raw.githubusercontent.com para a CDN jsDelivr, quando possível.
    Exemplos:
      https://raw.githubusercontent.com/OWNER/REPO/main/path/file.xsd
      https://raw.githubusercontent.com/OWNER/REPO/refs/heads/main/path/file.xsd
    Retorna a URL jsDelivr correspondente, ou None se não conseguir converter.
    """
    parsed = urlparse(url)
    if parsed.hostname not in {"raw.githubusercontent.com"}:
        return None

    # path esperado: /OWNER/REPO/BRANCH/RESTO...  ou  /OWNER/REPO/refs/heads/BRANCH/RESTO...
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 4:
        return None

    owner = parts[0]
    repo = parts[1]

    # Trata refs/heads/main
    if parts[2] == "refs" and len(parts) >= 5 and parts[3] == "heads":
        branch = parts[4]
        rest = parts[5:]
    else:
        branch = parts[2]
        rest = parts[3:]

    rest_path = "/".join(rest)
    # Formato jsDelivr: https://cdn.jsdelivr.net/gh/OWNER/REPO@BRANCH/RESTO
    return f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{rest_path}"


async def http_get_bytes_async(url: str, max_bytes: int) -> bytes:
    """
    Baixa conteúdo (XSD raiz) com httpx AsyncClient, usando headers e follow_redirects.
    Se receber 405/403 no RAW do GitHub, tenta fallback com jsDelivr.
    """
    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        follow_redirects=True,
        headers=DEFAULT_FETCH_HEADERS,
    ) as client:
        try:
            r = await client.get(url)
            # Fallback para jsDelivr se 405/403 ao acessar RAW GitHub
            if r.status_code in (403, 405):
                alt = raw_github_to_jsdelivr(url)
                if alt:
                    r = await client.get(alt)
            r.raise_for_status()
            content = r.content
            if len(content) > max_bytes:
                raise HTTPException(status_code=413, detail=f"Conteúdo muito grande em {url} (> {max_bytes} bytes)")
            return content
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail=f"Timeout ao baixar {url}")
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            raise HTTPException(status_code=502, detail=f"Falha ao baixar {url}: HTTP {status}")
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Erro ao baixar {url}: {str(e)}")


# ---------- Resolver síncrono para includes/imports (lxml) ----------
class HttpxResolver(etree.Resolver):
    """
    Resolver que intercepta carregamento de xs:include/xs:import.
    Usa httpx (síncrono) com os mesmos headers/timeout e também tenta fallback jsDelivr.
    """
    def __init__(self, timeout=(5.0, 20.0), headers=None):
        super().__init__()
        self.timeout = timeout
        self.headers = headers or DEFAULT_FETCH_HEADERS

    def resolve(self, url, id, context):
        try:
            # Tenta baixar a URL diretamente
            with httpx.Client(timeout=self.timeout, headers=self.headers, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code in (403, 405):
                    alt = raw_github_to_jsdelivr(url)
                    if alt:
                        resp = client.get(alt)
                resp.raise_for_status()
                data = resp.content
                # Entrega o conteúdo para o parser
                return self.resolve_string(data, context)
        except Exception as e:
            # Erro de rede — propaga, será exibido no error_log do schema
            raise


def build_schema(xsd_bytes: bytes, base_url: str) -> etree.XMLSchema:
    """
    Constrói o XMLSchema a partir do XSD raiz.
    Usa um XMLParser com HttpxResolver para resolver includes/imports remotos.
    """
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        huge_tree=False,
    )
    # Registra o resolver para includes/imports
    parser.resolvers.add(HttpxResolver(timeout=HTTP_TIMEOUT, headers=DEFAULT_FETCH_HEADERS))

    try:
        # base_url é fundamental para resolver caminhos relativos dos includes/imports
        xsd_doc = etree.parse(BytesIO(xsd_bytes), parser=parser, base_url=base_url)
    except etree.XMLSyntaxError as e:
        raise HTTPException(status_code=422, detail=f"XSD malformado: {str(e)}")

    try:
        schema = etree.XMLSchema(xsd_doc)
        return schema
    except etree.XMLSchemaParseError as e:
        # Erro ao montar o schema (includes ausentes, path errado, etc.)
        # A mensagem traz detalhes úteis do error_log.
        raise HTTPException(status_code=422, detail=f"Erro ao interpretar XSD: {str(e)}")


def validate_xml(schema: etree.XMLSchema, xml_str: str):
    """
    Valida o XML (string) contra o XMLSchema.
    Retorna (valid: bool, errors: list[str]).
    """
    # Parser seguro para o XML de entrada
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        huge_tree=True,  # pode habilitar documentos um pouco maiores
    )
    try:
        xml_doc = etree.fromstring(xml_str.encode("utf-8"), parser=parser)
    except etree.XMLSyntaxError as e:
        return False, [f"XML malformado: {str(e)}"]

    is_valid = schema.validate(xml_doc)
    if is_valid:
        return True, []
    else:
        # Coleta mensagens detalhadas do schema.error_log
        errs = [str(err) for err in schema.error_log]
        # Se vier vazio, ainda assim retorna genérico
        if not errs:
            errs = ["Documento inválido contra o XSD (sem detalhes no error_log)."]
        return False, errs


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.get("/", tags=["meta"])
def root():
    return {"name": APP_NAME, "version": APP_VERSION, "endpoints": ["/health", "/validate"]}


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "name": APP_NAME, "version": APP_VERSION}


@app.post("/validate", tags=["validate"])
async def validate(payload: ValidatePayload):
    """
    POST /validate
    Body:
      {
        "xml": "<xml ...>",
        "xsdUrl": "https://.../nfcom_v1.00.xsd"
      }
    Resposta:
      { "valid": true/false, "errors": [...], "warnings": [] }
    """
    # 1) Checagens iniciais
    if not payload.xml or not payload.xsdUrl:
        raise HTTPException(status_code=400, detail="Campos 'xml' e 'xsdUrl' são obrigatórios")

    if len(payload.xml.encode("utf-8")) > MAX_XML_BYTES:
        raise HTTPException(status_code=413, detail=f"XML muito grande (> {MAX_XML_BYTES} bytes)")

    if not is_host_allowed(str(payload.xsdUrl)):
        raise HTTPException(status_code=403, detail="Host do XSD não permitido pela política do serviço")

    # 2) Baixa o XSD raiz
    xsd_bytes = await http_get_bytes_async(str(payload.xsdUrl), MAX_XSD_BYTES)

    # 3) Constrói o XMLSchema com base_url e resolver para includes/imports
    schema = build_schema(xsd_bytes, base_url=str(payload.xsdUrl))

    # 4) Valida o XML
    valid, errors = validate_xml(schema, payload.xml)

    # 5) Resposta padronizada
    return {"valid": bool(valid), "errors": errors, "warnings": []}
