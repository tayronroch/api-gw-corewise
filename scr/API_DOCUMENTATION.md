# CoreWise Backend - API REST Documentation

## 📚 **Estrutura da API**

Base URL: `http://localhost:8000`

### 🔐 **Autenticação**

A API utiliza multiple métodos de autenticação:
- **JWT Tokens** (Recomendado para apps)
- **Session Authentication** (Django Admin)
- **Basic Authentication** (Desenvolvimento/Debug)

### 📋 **Endpoints Principais**

## 1. **USUÁRIOS** (`/api/users/`)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| GET | `/api/users/` | Listar usuários | ✅ Necessária |
| POST | `/api/users/` | Criar usuário | ✅ Necessária |
| GET | `/api/users/{id}/` | Detalhes do usuário | ✅ Necessária |
| PUT | `/api/users/{id}/` | Atualizar usuário | ✅ Necessária |
| DELETE | `/api/users/{id}/` | Excluir usuário | ✅ Necessária |

## 2. **TOPOLOGIA** (`/api/topology/`)

### 📡 **Equipamentos e Links** (DRF ViewSets)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| GET | `/api/topology/equipments/` | Listar equipamentos | ✅ Necessária |
| POST | `/api/topology/equipments/` | Criar equipamento | ✅ Necessária |
| GET | `/api/topology/equipments/{id}/` | Detalhes do equipamento | ✅ Necessária |
| PUT | `/api/topology/equipments/{id}/` | Atualizar equipamento | ✅ Necessária |
| DELETE | `/api/topology/equipments/{id}/` | Excluir equipamento | ✅ Necessária |
| GET | `/api/topology/links/` | Listar links | ✅ Necessária |
| POST | `/api/topology/links/` | Criar link | ✅ Necessária |
| GET | `/api/topology/links/{id}/` | Detalhes do link | ✅ Necessária |
| GET | `/api/topology/links/{id}/percentile95/` | Percentil 95 do link | ✅ Necessária |

### 🗺️ **Projetos de Topologia** (Topology Manager)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| GET | `/api/topology/topology-projects/` | Listar projetos | ❌ Público |
| GET | `/api/topology/topology-projects/{id}/` | Detalhes do projeto | ❌ Público |
| POST | `/api/topology/topology-projects/save/` | Salvar projeto | ❌ Público |
| DELETE | `/api/topology/topology-projects/{id}/delete/` | Excluir projeto | ❌ Público |
| POST | `/api/topology/topology-nodes/save/` | Salvar nós | ❌ Público |
| POST | `/api/topology/topology-connections/save/` | Salvar conexões | ❌ Público |

### 🎛️ **Topologia Interativa**

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| GET | `/api/topology/interactive/topology/` | Dados para visualização | ✅ Necessária |
| GET | `/api/topology/interactive/network-map/` | Mapa de rede interativo | ✅ Necessária |

### 🔧 **API Simplificada** (Sem GeoDjango)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| GET | `/api/topology/simple/test/` | Teste da API | ❌ Público |
| GET | `/api/topology/simple/projects/list/` | Listar projetos simples | ❌ Público |
| POST | `/api/topology/simple/projects/create/` | Criar projeto simples | ❌ Público |
| POST | `/api/topology/simple/projects/{id}/devices/add/` | Adicionar dispositivo | ❌ Público |
| POST | `/api/topology/simple/projects/{id}/connections/create/` | Criar conexão | ❌ Público |
| GET | `/api/topology/simple/projects/{id}/geojson/` | Dados GeoJSON | ❌ Público |
| GET | `/api/topology/simple/projects/{id}/summary/` | Resumo do projeto | ❌ Público |
| GET | `/api/topology/simple/devices/nearby/` | Dispositivos próximos | ❌ Público |

## 3. **ENGENHARIA** (`/api/engineering/`)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| GET | `/api/engineering/` | Endpoints de engenharia | ✅ Necessária |

## 4. **SEGURANÇA** (`/api/security/`)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| GET | `/api/security/` | Endpoints de segurança | ✅ Necessária |

## 📊 **Documentação da API**

| Endpoint | Descrição |
|----------|-----------|
| `/api/schema/` | Schema OpenAPI |
| `/api/docs/` | Documentação Swagger UI |
| `/api/redoc/` | Documentação ReDoc |

## MPLS Analyzer

Base: `/api/mpls/`

- Busca: `GET/POST /api/mpls/search/` (params: `q`, `type`, `limit`, `include_config`)
- Relatórios:
  - `GET /api/mpls/reports/customers/`
  - `GET /api/mpls/reports/equipment-summary/`
  - `GET /api/mpls/reports/network-topology/`
  - `GET /api/mpls/reports/vpn/` (filtros: `vpn_id`, `equipment`)
  - `GET /api/mpls/reports/customer-interfaces/` (filtro: `customer`)
  - `GET /api/mpls/reports/customers/excel/` (gera CSV com content-type Excel)

### Legacy (Compat)

Base: `/api/mpls/legacy/` — rotas antigas com cabeçalhos `Deprecation` e `Sunset`.

- `GET/POST /api/mpls/legacy/api/search/` → busca inteligente
- `GET /api/mpls/legacy/advanced-search/` → alias para busca avançada
- `GET /api/mpls/legacy/api/customer-report/` → relatório de clientes
- `GET /api/mpls/legacy/api/customer-report/excel/` → export CSV compatível com Excel
- `GET /api/mpls/legacy/api/vpn-report/` → wrapper de VPNs
- `GET /api/mpls/legacy/api/customer-interface-report/` → wrapper de interfaces por cliente
- `GET /api/mpls/legacy/api/update-status/` → estatísticas do sistema

Consulte `/api/docs/` para detalhes e marque rotas legacy como deprecated.

#### Exemplos

Buscar via legacy (deprecado):
```bash
curl -i \
  -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/api/mpls/legacy/api/search/?q=10.0.0.1&limit=10"
```
Repare nos headers `Deprecation: true` e `Sunset: <date>`.

Relatório de VPNs (novo):
```bash
curl -s \
  -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/api/mpls/reports/vpn/?vpn_id=123"
```

## 📝 **Exemplos de Uso**

### **1. Listar Projetos de Topologia**
```bash
curl -X GET "http://localhost:8000/api/topology/topology-projects/" \
  -H "Accept: application/json"
```

**Resposta:**
```json
[
  {
    "id": "topology_1754680345686_vg78ub5r0",
    "name": "Projeto Exemplo",
    "description": "Descrição do projeto",
    "nodes": [...],
    "connections": [...],
    "created_at": "2025-08-08T17:22:51.072350-05:00",
    "updated_at": "2025-08-08T17:22:51.072399-05:00"
  }
]
```

### **2. Obter Projeto Específico**
```bash
curl -X GET "http://localhost:8000/api/topology/topology-projects/{project_id}/" \
  -H "Accept: application/json"
```

### **3. Salvar Nós de Topologia**
```bash
curl -X POST "http://localhost:8000/api/topology/topology-nodes/save/" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "topology_123",
    "nodes": [
      {
        "id": "node_1",
        "name": "Router Principal",
        "node_type": "router",
        "latitude": -23.5505,
        "longitude": -46.6333
      }
    ]
  }'
```

## ⚙️ **Configurações**

### **Rate Limiting**
- **Anônimos**: 100 requests/hora
- **Usuários autenticados**: 1000 requests/hora

### **CORS**
Origens permitidas para desenvolvimento:
- `http://localhost:3000`
- `http://localhost:3001`
- `http://localhost:3003`
- `http://127.0.0.1:3000`

### **Paginação**
- **Padrão**: 20 itens por página
- **Parâmetros**: `?page=1&page_size=50`

## 🔒 **Segurança**

- **HTTPS**: Obrigatório em produção
- **CSRF Protection**: Habilitado
- **Rate Limiting**: django-axes
- **Session Security**: Cookies seguros

## 🐛 **Debug e Desenvolvimento**

Para desenvolvimento, use:
```bash
# Verificar se API está respondendo
curl -I http://localhost:8000/api/topology/topology-projects/

# Testar com dados JSON
curl -X GET http://localhost:8000/api/topology/topology-projects/ | jq
```

## 📈 **Status Codes**

| Código | Descrição |
|--------|-----------|
| 200 | Sucesso |
| 201 | Criado com sucesso |
| 400 | Dados inválidos |
| 401 | Não autorizado |
| 403 | Proibido |
| 404 | Não encontrado |
| 429 | Rate limit excedido |
| 500 | Erro interno do servidor |
