"""
API Schema & Documentation Endpoint Discoverer
Probes for Swagger UI, OpenAPI JSON/YAML specifications, GraphQL playgrounds, and Postman collections.
"""

from typing import Dict, Any, List
import requests

API_DOC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger/index.html",
    "/graphql",
    "/graphiql"
]

def discover_api_schemas(domain: str) -> List[Dict[str, Any]]:
    """Probes for open API documentation and endpoints."""
    discovered = []
    base_url = f"https://{domain}"

    for path in API_DOC_PATHS:
        try:
            r = requests.get(f"{base_url}{path}", timeout=4, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
            if r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower() or "graphql" in r.text.lower()):
                discovered.append({
                    "path": path,
                    "url": f"{base_url}{path}",
                    "type": "GraphQL" if "graph" in path else "OpenAPI/Swagger",
                    "status_code": r.status_code
                })
        except Exception:
            pass

    return discovered
