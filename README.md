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

## 📋 **Estrutura do Banco de Dados**

### **🗂️ Multi-Database Architecture**

O sistema utiliza uma arquitetura multi-database para separar responsabilidades:

```
/src/
├── 🎯 mpls_db.sqlite3                    # Banco MPLS Analyzer (dados de rede)
├── db.sqlite3                            # Banco padrão (core, users, auth)
└── modules/mpls_analyzer/
    ├── db.sqlite3                        # Cópia do banco mpls
    └── backup_db_20250823_211211.sqlite3 # Backup automático
```

### **⚙️ Configuração dos Bancos**

```python
DATABASES = {
    'default': {  # Core, users, authentication
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    },
    'mpls': {     # MPLS Analyzer (dados de rede)
        'ENGINE': 'django.db.backends.sqlite3', 
        'NAME': BASE_DIR / 'mpls_db.sqlite3',
    }
}

DATABASE_ROUTERS = ['core.db_router.MPLSRouter']
```

### **📊 MPLS Database - Dados Atuais**

| Tabela | Registros | Descrição |
|--------|-----------|-----------|
| **Equipment** | 103 | Equipamentos de rede MPLS |
| **VPN** | 1.183 | VPNs MPLS configuradas |
| **Interface** | 523 | Interfaces com descrições completas |
| **CustomerService** | 715 | Serviços de clientes |
| **VpwsGroup** | 733 | Grupos VPWS |
| **LDPNeighbor** | 909 | Vizinhos LDP |
| **LAGMember** | 30 | Membros de interfaces LAG |

### **🔄 Relacionamentos dos Dados**

```
Equipment (1) ──→ (N) MPLSConfiguration
                    ├─→ (N) Interface (descrições, tipos, velocidades)
                    └─→ (N) VpwsGroup
                              └─→ (N) Vpn 
                                    └─→ (N) CustomerService
```

### **🎯 APIs Disponíveis**

#### **Busca Inteligente**
- **GET** `/api/mpls-analyzer/search/?q={term}`
- Busca por: equipamento, cliente, VPN ID, IP, localização
- Retorna: equipamentos + suas VPNs automaticamente

#### **Relatório por Equipamento**
- **GET** `/api/mpls-analyzer/reports/equipment/?equipment={name}`
- Retorna: estrutura completa com todas VPNs do equipamento
- Inclui: descrições de interface, detalhes LAG, dados de vizinhança

#### **Relatório por Cliente**
- **GET** `/api/mpls-analyzer/reports/customers/?customer={name}`
- Retorna: todas VPNs do cliente com sides A e B (pontas Martini)
- Inclui: serviços sem duplicação, encapsulamento completo

### **✨ Recursos Especiais**

- **🔍 Busca Inteligente**: Resultados contextualmente relevantes
- **🔗 LAG Support**: Interfaces agregadas com membros
- **📝 Descrições Completas**: 100% das interfaces têm descrição
- **⚠️ Fallback Robusto**: Interfaces não mapeadas são inferidas
- **🔐 Auditoria Completa**: Logs de acesso e ações
- **🛡️ Sem Duplicação**: Serviços únicos por VPN

### **📈 Status do Sistema**

- **Tamanho do Banco**: ~1.1 MB
- **Última Atualização**: 18/08/2025
- **Integridade**: ✅ 100% funcional
- **Performance**: Otimizada com select_related/prefetch_related
- **Documentação**: OpenAPI/Swagger automática
