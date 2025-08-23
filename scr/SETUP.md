# Setup para Múltiplas Estações de Trabalho

## Problemas de Compatibilidade

Este projeto possui dependências específicas que podem variar entre diferentes estações de trabalho, especialmente relacionadas ao GDAL (Geographic Data Abstraction Library).

## Solução Implementada

### 1. Verificação da Versão GDAL do Sistema
Antes de instalar as dependências Python, verifique a versão do GDAL instalada no sistema:

```bash
gdal-config --version
```

### 2. Configuração do Ambiente Virtual

```bash
# Criar e ativar ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Verificar versão GDAL do sistema
GDAL_VERSION=$(gdal-config --version)
echo "Versão GDAL do sistema: $GDAL_VERSION"

# Instalar GDAL Python compatível com a versão do sistema
pip install GDAL==$GDAL_VERSION

# Instalar demais dependências
pip install -r requirements.txt
```

### 3. Arquivo requirements.txt Atualizado

O arquivo `requirements.txt` foi atualizado com:
- Versioning constraint para GDAL: `GDAL>=3.4.0,<3.9.0`
- Comentários explicativos sobre compatibilidade

### 4. Arquivo de Versões Exatas

Para maior reprodutibilidade, foi criado `requirements-freeze.txt` com versões exatas de todas as dependências.

## Instalação Automática

Para nova estação de trabalho:

```bash
# Clone do repositório
git clone <repository-url>
cd CoreWise/backend

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependências
pip install -r requirements-freeze.txt

# OU para versões flexíveis:
pip install -r requirements.txt
```

## Solução de Problemas

### Erro "No module named 'axes'"
```bash
pip install django-axes
```

### Erro de incompatibilidade GDAL
```bash
# Verificar versão do sistema
gdal-config --version

# Instalar versão compatível
pip install GDAL==<versao_sistema>
```

### Dependências do sistema (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install gdal-bin libgdal-dev python3-gdal
```

## Verificação

Teste se o ambiente está funcionando:
```bash
python3 manage.py check
python3 manage.py runserver
```

## Notas Importantes

1. O GDAL Python deve sempre ser compatível com a versão do sistema
2. Use `requirements-freeze.txt` para reprodução exata do ambiente
3. Sempre ative o ambiente virtual antes de trabalhar no projeto
4. Em caso de problemas, delete o `venv` e recrie seguindo estes passos