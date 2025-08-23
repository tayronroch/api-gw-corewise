# MPLS Search System (SearchBackbone)

Sistema Django para busca e análise de configurações MPLS (VPN/VPWS, interfaces e clientes) com autenticação, auditoria e APIs de consulta.

## Visão Geral

- App Django: `mpls_analyzer`
- Projeto Django: `mpls_search_system`
- Banco padrão: SQLite (desenvolvimento). Suporte opcional a PostgreSQL para full‑text search (com fallbacks prontos).
- MFA e OTP: presentes, porém simplificados/desativados em desenvolvimento.

## Estrutura do Projeto

```
.
├── manage.py                      # Utilitário de gestão Django
├── requirements.txt               # Dependências
├── mpls_search_system/            # Projeto (settings/urls/etc.)
│   ├── settings.py                # Configurações (SQLite por padrão)
│   ├── urls.py                    # Inclui urls do app
│   ├── asgi.py / wsgi.py          # Entradas ASGI/WSGI
│   └── __init__.py
└── mpls_analyzer/                 # App principal
    ├── urls.py                    # Rotas do app (web e API)
    ├── views.py                   # Lógica das páginas e APIs
    ├── models.py                  # Modelos (Equipment/Vpn/etc.)
    ├── forms.py                   # Formulários (usuários, perfil, busca)
    ├── search_utils.py            # Motor de busca (SQLite fallback)
    ├── parsers.py                 # Parser de configs/JSON DMOS + persistência
    ├── audit.py                   # Logger de auditoria (AuditLog)
    ├── security.py                # Utilidades de segurança e MFA (dev simplificado)
    ├── middleware.py              # Logs de acesso + contexto de auditoria
    ├── templates/mpls_analyzer/   # Templates HTML
    │   ├── base.html, login.html, dashboard.html, search.html, ...
    │   └── pages de auditoria, usuário, segurança, relatórios
    ├── management/commands/       # Comandos de gestão (processamento de backups)
    │   ├── update_database.py
    │   ├── process_backup_directory.py
    │   ├── process_clean_backup_directory.py
    │   ├── process_json_config.py
    │   └── update_encapsulation_types.py
    └── scripts/                   # Scripts auxiliares (backup/scan/fix)
        ├── scan_and_backup.sh, scan-network.py
        ├── easy-bkp-optimized.py, easy-bkp-simplified.py
        └── smart-json-fix.py      # Correção de JSONs malformados
```

## Modelos (dados)

- Equipment: `name`, `ip_address`, `location`, `equipment_type` (PE/CE/P), `status`, `last_backup`.
- MplsConfiguration: vínculo com `equipment`, `backup_date`, `raw_config`. Campo `search_vector` (PostgreSQL) com fallback em SQLite.
- VpwsGroup: grupo VPWS por configuração (`group_name`).
- Vpn: `vpn_id`, `neighbor_ip/hostname`, `pw_type/pw_id`, `encapsulation` e `encapsulation_type` (untagged/vlan_tagged/qinq), `access_interface`.
- Interface: física ou `lag`, `description`, `speed`, `is_customer_interface`.
- LagMember: membros de uma interface LAG.
- CustomerService: serviços associados à `vpn` (internet/vpn/voice/data) e `bandwidth`.
- BackupProcessLog: logs de processamento de diretórios de backup.
- AccessLog: histórico de login/logout/sucesso/falha.
- AuditLog: auditoria detalhada (ação, alvo, busca, exportações).
- SecuritySettings: políticas globais (tentativas, lockout, senha, IP whitelist, sessão).
- UserProfile: preferências do usuário (MFA, admin, bloqueio, mfa_secret).
- LoginAttempt: tentativas de login para controle/bloqueio por IP/usuário.

## Rotas

Base do projeto inclui as URLs do app (`/` → `mpls_analyzer.urls`). Principais endpoints:

- Autenticação
  - `GET/POST /login/` → `login_view`
  - `GET /logout/` → `logout_view`
  - `GET /setup-mfa/`, `GET /verify-mfa/` → redirecionam em dev

- Dashboard e Busca
  - `GET /dashboard/` → estatísticas gerais
  - `GET /search/` → busca inteligente com destaques
  - `GET /advanced-search/` → busca avançada (filtros)
  - `GET /equipment/<id>/` → detalhes por equipamento

- Atualizações e Correções
  - `GET/POST /update-database/` → executar processamento de backups via comandos
  - `GET/POST /fix-malformed-json/` → executar `smart-json-fix.py`

- Relatórios
  - `GET /customer-report/` → página de relatório por cliente
  - `GET /api/customer-report/` → JSON detalhado lado A/B por cliente (`?customer=...`)
  - `GET /api/customer-report/excel/` → exporta XLSX do relatório de cliente
  - `GET /api/vpn-report/` → relatório por VPN ID (`?vpn_id=...`)
  - `GET /api/customer-interface-report/` → interfaces de clientes por equipamento (`?equipment=...`)

- API de busca (AJAX)
  - `GET /api/search/?q=...` → retorna VPNs/serviços relacionados

- Administração/Usuários
  - `GET /admin-panel/` → painel administrativo (requer admin)
  - `GET /admin/users/` → lista de usuários (filtros)
  - `GET/POST /admin/users/<id>/` → detalhes/ações
  - `GET/POST /admin/users/create/` → criação
  - `GET /users/` → gerenciamento básico
  - `GET/POST /users/create/`, `/users/<id>/edit/`, `/users/<id>/toggle-status/`, `/users/<id>/delete/`
  - Perfil: `/profile/`, `/profile/change-password/`, `/profile/setup-mfa/`, `/profile/disable-mfa/`, `/profile/toggle-mfa/`

- Auditoria e Segurança
  - `GET /manager/audit-dashboard/`, `/manager/access-logs/`, `/manager/audit-logs/`
  - `GET /manager/access-logs/export/`, `/manager/audit-logs/export/`
  - `GET/POST /manager/security-settings/` → configura políticas globais

Notas:
- A maioria das rotas exige login (`@require_mfa` em modo dev exige apenas autenticação).
- Alguns templates de páginas administrativas referenciados em `views.py` podem não existir em `templates/`; ajuste conforme necessário.

## Como funciona (fluxos principais)

- Login e segurança
  - `security.require_mfa`: em desenvolvimento apenas valida login; MFA real pode ser reativado conforme comentários no código.
  - `middleware.AuditMiddleware` injeta IP/User-Agent no request para auditoria; `middleware` também registra logins/logouts e falhas.
  - `SecuritySettings` controla tentativas, lockout, sessão e políticas de senha; `LoginAttempt` implementa bloqueios por IP/usuário.

- Busca
  - `search_utils.smart_search` detecta tipo (IP, MAC, VLAN, interface, serial, texto) e usa `AdvancedSearchEngine` com filtros e destaques.
  - Em SQLite, usa `icontains` e regex; em PostgreSQL, há ganchos para `SearchVector` (fallbacks implementados).

- Parser e atualização de banco
  - `parsers.MplsConfigParser` processa arquivos de configuração CLI e JSON DMOS (incluindo formato estruturado com metadata) e extrai VPWS/VPNs, interfaces de clientes, LAGs e vizinhos LDP.
  - Persistência em `save_to_database` (parte do parser) cria/atualiza `Equipment`, `MplsConfiguration`, grupos `Vpws`, `Vpn`, `Interface` e membros.
  - Auditoria via `audit.log_audit_action` em buscas/relatórios/exportações.

## Comandos de Gestão

- `python manage.py update_database [--backup-dir DIR | --all-backups] [--user USER]`
  - Processa diretórios `mpls_analyzer/scripts/backup_*` (ou um diretório específico) com `BackupProcessor` e registra `BackupProcessLog`.

- `python manage.py process_backup_directory <backup_dir> [--dry-run] [--force]`
  - Varre `.txt` e auto‑detecta CLI ou JSON; aplica correções de JSON e salva via parser.

- `python manage.py process_clean_backup_directory <backup_dir> [--dry-run] [--force]`
  - Varre estrutura nova (subpastas com `config.json` e arquivos `.json` diretos) e processa via parser.

- `python manage.py process_json_config <arquivo.json> [--dry-run]`
  - Processa um único JSON DMOS, mostra resumo e salva (se não for dry‑run).

- `python manage.py update_encapsulation_types`
  - Recalcula `encapsulation_type` das VPNs existentes.

- `python manage.py createsuperuser`, `migrate`, etc. (padrões Django).

## Templates

Diretório `mpls_analyzer/templates/mpls_analyzer/` inclui páginas para:
- Autenticação: `login.html`, `verify_mfa.html`, `setup_mfa.html`, `disable_mfa.html`.
- Dashboard/Busca: `dashboard.html`, `search.html`, `customer_report.html`.
- Administração/Usuário: `user_management.html`, `create_user.html`, `edit_user.html`, `user_profile.html`, `change_password.html`.
- Auditoria/Security: `audit_dashboard.html`, `access_logs.html`, `audit_logs.html`, `security_settings.html`.
- Operações: `update_database.html`, `fix_malformed_json.html`.

Observação: Views administrativas adicionais referenciam `mpls_analyzer/admin/*.html` que não estão no repositório; crie esses templates se for utilizar tais rotas.

## Executando em Desenvolvimento

1) Criar ambiente e instalar dependências
```
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

2) Migrar banco e criar usuário
```
python manage.py migrate
python manage.py createsuperuser
```

3) Rodar servidor
```
python manage.py runserver
```

4) (Opcional) Processar backups
```
python manage.py update_database --all-backups
# ou
python manage.py process_backup_directory mpls_analyzer/scripts/backup_YYYY-MM-DD
```

Credenciais e segurança: ajuste `DEBUG`, `ALLOWED_HOSTS` e `SECRET_KEY` via variáveis de ambiente conforme `settings.py` (usa `python-decouple`, com defaults seguros apenas para dev). O rate limiting está desativado por padrão (`RATELIMIT_ENABLE=False`).

## APIs (detalhes)

- `GET /api/search/?q=<termo>`
  - Retorna lista de VPNs/serviços relacionados à busca (prioriza VPN ID numérica; busca por cliente retorna suas VPNs).

- `GET /api/vpn-report/?vpn_id=<int>`
  - Relaciona ponta A e B, interface de acesso, encapsulamento e clientes.

- `GET /api/customer-interface-report/?equipment=<nome>`
  - Lista interfaces marcadas como de cliente e VPNs associadas, agrupando por equipamento.

- `GET /api/customer-report/?customer=<nome>` e `GET /api/customer-report/excel/?customer=<nome>`
  - JSON ou planilha XLSX com pares A/B por VPN do cliente, incluindo encapsulamento e interfaces (detalha LAGs e membros quando aplicável).

Todas as APIs (exceto login) exigem autenticação.

## Segurança

- Headers: adicionados por `security.SecurityMiddleware` (CSP, X-Frame-Options, etc.).
- Políticas: `SecuritySettings` define tentativas/lockout, sessão e regras de senha. Em produção, ative `DEBUG=False` e HTTPS para cookies e HSTS (ver `settings.py`).
- MFA: funções presentes, porém substituídas por no‑ops em dev; reative conforme comentários no código (`django-otp`, TOTP).

## Scripts úteis

- `scripts/scan-network.py`, `scan_and_backup.sh`: varredura e coleta de configs.
- `scripts/easy-bkp-optimized.py`, `easy-bkp-simplified.py`: rotinas de backup.
- `scripts/smart-json-fix.py`: corrige JSONs DMOS malformados, usado pela tela de correção.

## Observações e To‑dos

- Alguns templates referenciados em rotas administrativas não estão no repositório e podem ser necessários caso use essas páginas.
- O mecanismo de busca usa fallback para SQLite; para grandes volumes e ranking, considerar PostgreSQL e habilitar `SearchVector` no modelo.

---

Desenvolvido para acelerar troubleshooting e inventário de redes MPLS.

## Diagramas

### Modelo de Dados (simplificado)

```
┌─────────────┐       1    *    ┌────────────────────┐      1    *    ┌──────────┐
│  Equipment  │───────────────▶│ MplsConfiguration  │───────────────▶│ VpwsGroup │
└─────┬───────┘                 └──────────┬─────────┘                └─────┬────┘
      │                                     │                               │
      │ 1    *                              │ 1         *                   │ 1   *
      ▼                                     ▼                               ▼
┌─────────────┐                       ┌───────────────┐               ┌──────────┐
│  Interface  │◀──────────────────────│   Vpn         │◀──────────────│Customer  │
└─────┬───────┘ 1   *                 └──────┬────────┘   1    *      │ Service  │
      │                                      │                         └──────────┘
      ▼                                      │
┌─────────────┐                              │
│  LagMember  │                              │
└─────────────┘                              │
                                             │
                                      (opcional) neighbor_hostname

Usuários e Segurança/Auditoria
┌───────┐ 1 ─── 1 ┌──────────────┐      1  *  ┌───────────┐
│ User  │────────▶│ UserProfile  │──────────▶│ AccessLog │
└───┬───┘         └──────────────┘            └───────────┘
    │ 1  *                                      1  *
    └──────────────▶┌───────────┐              ┌────────────┐
                    │ AuditLog  │◀────────────▶│ LoginAttempt│
                    └───────────┘              └────────────┘

SecuritySettings: singleton (ID=1) com políticas globais.
```

### Fluxo de Processamento de Backups

```
Diretório de backup (.txt/.json) ──▶ Commands (process_* / update_database)
   └─ lê arquivo(s) ──▶ parsers.MplsConfigParser (auto-detecção CLI/DMOS)
       └─ extrai VPWS/VPN/Interfaces/LAG/Clientes
           └─ save_to_database() ▶ cria/atualiza Equipment, MplsConfiguration,
                                   VpwsGroup, Vpn, Interface, LagMember, CustomerService
               └─ registra BackupProcessLog
```

## Guia de Rotas (com exemplos)

- GET /login/
  - Página de login; em dev, autentica e redireciona ao dashboard.

- GET /dashboard/
  - Estatísticas gerais (equipamentos, clientes, VPNs, últimos backups).

- GET /search/?q=<termo>
  - Busca inteligente com destaque em resultados de configuração.

- GET /advanced-search/
  - Busca com filtros (equipamento, localização).

- GET /equipment/<id>/
  - Detalhes de um equipamento e últimas configurações.

- GET/POST /update-database/
  - Interface para disparar comandos de processamento de backup.

- GET/POST /fix-malformed-json/
  - Executa script de correção de JSONs (smart-json-fix.py).

### APIs

1) GET `/api/search/?q=3502`

Request:
```
GET /api/search/?q=3502
```

Resposta (200):
```
{
  "results": [
    {
      "type": "vpn",
      "vpn_id": 3502,
      "equipment_name": "MA-CANABRAVA-PE01",
      "equipment_id": 1,
      "loopback_ip": "10.254.254.47",
      "neighbor_ip": "10.254.254.29",
      "neighbor_hostname": "",
      "access_interface": "ten-gigabit-ethernet-1/1/4",
      "encapsulation": "qinq:209 210",
      "description": "",
      "group_name": "PI-PARNAIBA-PE01",
      "customers": ["ULTRANET"]
    }
  ]
}
```

2) GET `/api/vpn-report/?vpn_id=3502`

Request:
```
GET /api/vpn-report/?vpn_id=3502
```

Resposta (200):
```
{
  "results": [
    {
      "vpn_id": 3502,
      "encapsulation": "qinq:209 210",
      "encapsulation_type": "qinq",
      "access_interface": "ten-gigabit-ethernet-1/1/4",
      "access_interface_details": {
        "name": "ten-gigabit-ethernet-1/1/4",
        "description": "CUSTOMER-ISP-ULTRANET-L2L-VL209-210",
        "type": "physical",
        "speed": "10G",
        "is_customer": true
      },
      "description": "",
      "pw_type": "vlan",
      "pw_id": 3502,
      "equipment_a": {
        "hostname": "MA-CANABRAVA-PE01",
        "loopback_ip": "10.254.254.47",
        "location": "MA-CANABRAVA"
      },
      "equipment_b": {
        "loopback_ip": "10.254.254.29",
        "hostname": ""
      },
      "peer_equipment": [
        { "hostname": "PI-PARNAIBA-PE01", "loopback_ip": "10.254.254.29", "access_interface": "...", "encapsulation": "...", "encapsulation_type": "..." }
      ],
      "customers": ["ULTRANET"]
    }
  ]
}
```

Erros comuns:
- `400 {"error": "vpn_id obrigatório"}` quando `vpn_id` ausente.
- `400 {"error": "vpn_id inválido"}` quando não numérico.

3) GET `/api/customer-interface-report/?equipment=MA-CANABRAVA-PE01`

Request:
```
GET /api/customer-interface-report/?equipment=MA-CANABRAVA-PE01
```

Resposta (200):
```
{
  "results": [
    {
      "equipment": {
        "hostname": "MA-CANABRAVA-PE01",
        "loopback_ip": "10.254.254.47",
        "location": "MA-CANABRAVA"
      },
      "interface": {
        "name": "ten-gigabit-ethernet-1/1/4",
        "description": "CUSTOMER-ISP-ULTRANET-L2L-VL209-210",
        "type": "physical",
        "speed": "10G"
      },
      "vpns": [
        {
          "vpn_id": 3502,
          "neighbor_ip": "10.254.254.29",
          "neighbor_hostname": "",
          "description": "",
          "encapsulation": "qinq:209 210",
          "encapsulation_type": "qinq",
          "customers": ["ULTRANET"]
        }
      ],
      "customers": ["ULTRANET"]
    }
  ]
}
```

4) GET `/api/customer-report/?customer=ULTRANET`

Request:
```
GET /api/customer-report/?customer=ULTRANET
```

Resposta (200) resumida:
```
{
  "results": [
    {
      "vpn_id": 3502,
      "description": "",
      "pw_type": "vlan",
      "pw_id": 3502,
      "side_a": {
        "equipment": {"hostname": "MA-CANABRAVA-PE01", "loopback_ip": "10.254.254.47", "location": "MA-CANABRAVA"},
        "neighbor": {"hostname": "PI-PARNAIBA-PE01", "loopback_ip": "10.254.254.29"},
        "access_interface": "ten-gigabit-ethernet-1/1/4",
        "access_interface_details": {"name": "...", "description": "...", "type": "physical", "speed": "10G", "is_customer": true},
        "vpws_group": "PI-PARNAIBA-PE01",
        "encapsulation_details": {"type": "qinq", "raw": "qinq:209 210", "vlans": [209, 210]}
      },
      "side_b": { "equipment": {"hostname": "..."}, "access_interface": "...", "encapsulation_details": {"type": "..."} },
      "customers": ["ULTRANET"]
    }
  ]
}
```

Erros:
- `400 {"error": "Nome do cliente é obrigatório"}` se `customer` ausente.

5) GET `/api/customer-report/excel/?customer=ULTRANET`

- Retorna arquivo XLSX com colunas de A/B, interfaces e encapsulamentos.

Permissões:
- Todas as APIs acima requerem autenticação; em dev, `require_mfa` apenas verifica login.
