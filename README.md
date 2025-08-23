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
  manage.py / settings.py...
