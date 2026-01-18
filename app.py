from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import List
from io import BytesIO
import httpx
from lxml import etree

app = FastAPI(title="NeuroFiscal XSD Validator", version="1.0.0")

# Limites de segurança simples
MAX_XML_BYTES = 2_000_000
MAX_XSD_BYTES = 2_000_000
HTTP_TIMEOUT = (3.0, 10.0)  # (conexão, leitura) em segundos

class ValidatePayload(BaseModel):
    xml: str
    xsdUrl: HttpUrl

async def http_get_bytes(url: str, max_bytes: int) -> bytes:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        r = await client.get(url)
        r.raise_for_status()
        content = r.content
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"Conteúdo muito grande em {url}")
        return content

def build_schema(xsd_bytes: bytes, base_url: str) -> etree.XMLSchema:
    # base_url é essencial para resolver includes/imports relativos
    parser = etree.XMLParser(resolve_entities=False, huge_tree=False)
    xsd_doc = etree.parse(BytesIO(xsd_bytes), parser=parser, base_url=base_url)
    try:
        return etree.XMLSchema(xsd_doc)
    except etree.XMLSchemaParseError as e:
        raise HTTPException(status_code=422, detail=f"Erro ao interpretar XSD: {str(e)}")

def validate_xml(schema: etree.XMLSchema, xml_str: str):
    parser = etree.XMLParser(resolve_entities=False, huge_tree=True)
    try:
        xml_doc = etree.fromstring(xml_str.encode("utf-8"), parser=parser)
    except etree.XMLSyntaxError as e:
        return False, [str(e)]
    ok = schema.validate(xml_doc)
    if ok:
        return True, []
    else:
        return False, [str(err) for err in schema.error_log]

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/validate")
async def validate(payload: ValidatePayload):
    if len(payload.xml.encode("utf-8")) > MAX_XML_BYTES:
        raise HTTPException(status_code=413, detail="XML muito grande")
    # 1) Baixa o XSD
    try:
        xsd_bytes = await http_get_bytes(str(payload.xsdUrl), MAX_XSD_BYTES)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Timeout ao baixar o XSD")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Falha ao baixar XSD: HTTP {e.response.status_code}")
    # 2) Constrói o schema com base_url para resolver includes/imports
    schema = build_schema(xsd_bytes, str(payload.xsdUrl))
    # 3) Valida
    valid, errors = validate_xml(schema, payload.xml)
    # 4) Sempre retorna 200 com {valid, errors}
    return {"valid": bool(valid), "errors": errors, "warnings": []}
