# api-gw-corewise

┌───────────────────────────────────────────────────┐
│                    FRONTEND (React)               │
└─────────────────────┬─────────────────────────────┘
                      │
                      ▼
┌───────────────────────────────────────────────────┐
│                    CORE (API Gateway)             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │
│  │   Auth      │ │   Router    │ │   Load      │  │
│  │  Service    │ │  Service    │ │  Balancer   │  │
│  └─────────────┘ └─────────────┘ └─────────────┘  │
└───────────────────────────────────────────────────┘
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │   MPLS      │ │  Topology   │ │ Networking  │
    │ Analyzer    │ │   Service   │ │  Service    │
    │ Service     │ │             │ │             │
    └─────────────┘ └─────────────┘ └─────────────┘


src/
  config/                    # pacote do projeto (Django)
    settings.py              # configurações globais (apps, middleware, DB, JWT, CORS)
    urls.py                  # roteamento raiz: inclui api.v1, health e docs
    asgi.py                  # entrypoint ASGI (Uvicorn/Daphne)
    wsgi.py                  # entrypoint WSGI (Gunicorn/uWSGI)
  core/                      # gateway fino
    services/
      api_gateway.py
      load_balancer.py
      auth_service.py
      circuit_breaker.py
      service_registry.py
    middleware.py
    utils/
      metrics.py
      config.py
  modules/                   # domínios (apenas adapters/clients)
    mpls/
      __init__.py
      client.py
      schemas.py             # Pydantic/DRF serializers p/ contratos
      settings.py
    topology/
      __init__.py
      client.py
      schemas.py
      settings.py
    networking/
      __init__.py
      client.py
      schemas.py
      settings.py
  api/
    v1/
      urls.py
      views.py               # mapeia -> modules.<domínio>.client
    health/
      urls.py
      views.py
  contracts/                 # OpenAPI/JSON Schemas dos upstreams
  tests/
  manage.py                  # aponta para DJANGO_SETTINGS_MODULE=config.settings

Executar localmente
- `cd src`
- `./venv/bin/python manage.py runserver 0.0.0.0:8000`

Rotas utilitárias
- Health: `/health/live`, `/health/ready`
- Docs: `/api/docs` (Swagger), `/api/redoc`, `/api/schema`
- Ping v1: `/api/v1/ping`

Testes com Postman/Newman (smoke)
- Importar `src/postman_collection.json` no Postman para testar manualmente.
- Rodar automatizado com Newman:
  - `npm run smoke` (usa o `newman` local do projeto)
  - Ajuste `base_url` conforme o ambiente: `npm run smoke -- --env-var base_url=http://127.0.0.1:8000`

## 🛠️ **Solução Rápida - Explicação do Problema:**

Os grupos estão vazios porque **faltam os `tags`** nos decorators `@extend_schema`. Para corrigir isso rapidamente, preciso adicionar o parâmetro `tags=['nome-do-grupo']` em cada decorator.

**Exemplo da correção necessária:**

```python
<code_block_to_apply_changes_from>
```

**O que precisa ser feito:**

1. **Adicionar `tags=['mpls-search']`** no primeiro endpoint (busca)
2. **Adicionar `tags=['mpls-reports']`** nos endpoints de relatórios 
3. **Adicionar `tags=['mpls-admin']`** nos endpoints administrativos

**Por isso os grupos aparecem mas estão vazios** - o DRF Spectacular criou os grupos baseado na configuração do `SPECTACULAR_SETTINGS`, mas não consegue associar os endpoints aos grupos porque não têm os tags especificados.

Quer que eu corrija o arquivo agora ou você prefere fazer essa correção manualmente? É só adicionar a linha `tags=['nome-do-grupo'],` em cada `@extend_schema`. 🔧
