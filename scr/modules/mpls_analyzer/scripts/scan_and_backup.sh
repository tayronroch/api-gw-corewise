#!/bin/bash

# Script para executar scan da rede seguido de backup completo
# Autor: Sistema automatizado
# Data: 2025-08-22

# Configurações
SCRIPT_DIR="/home/tayron/Documentos/GitHub/SeachBackbone/mpls_analyzer/scripts"
PROJECT_DIR="/home/tayron/Documentos/GitHub/SeachBackbone"
LOG_FILE="/home/tayron/Documentos/GitHub/SeachBackbone/scan_backup.log"

# Função para log com timestamp
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Início do script
log_message "=== INICIANDO SCAN + BACKUP AUTOMATIZADO ==="

# Configurar variáveis de ambiente
export DEVICE_USERNAME="${DEVICE_USERNAME:-corewise}"
export DEVICE_PASSWORD="${DEVICE_PASSWORD:-TA@1320**r}"

# Mudar para o diretório dos scripts
cd "$SCRIPT_DIR" || {
    log_message "ERRO: Não foi possível acessar o diretório $SCRIPT_DIR"
    exit 1
}

# ETAPA 1: Executar scan da rede
log_message "🔍 ETAPA 1: Executando scan da rede..."
log_message "Atualizando lista de equipamentos..."

timeout 300s python scan-network.py >> "$LOG_FILE" 2>&1
SCAN_EXIT_CODE=$?

if [ $SCAN_EXIT_CODE -eq 0 ]; then
    log_message "✅ Scan da rede concluído com sucesso"
elif [ $SCAN_EXIT_CODE -eq 124 ]; then
    log_message "⚠️ Scan interrompido por timeout, mas pode ter encontrado alguns equipamentos"
else
    log_message "❌ Erro no scan da rede (código: $SCAN_EXIT_CODE)"
fi

# Verificar se o arquivo banco-de-dados.json existe
if [ ! -f "banco-de-dados.json" ]; then
    log_message "❌ ERRO: Arquivo banco-de-dados.json não foi encontrado após o scan"
    exit 1
fi

# Contar dispositivos encontrados
DEVICE_COUNT=$(python -c "import json; data=json.load(open('banco-de-dados.json')); print(len(data))" 2>/dev/null || echo "0")
log_message "📋 Dispositivos registrados: $DEVICE_COUNT"

# ETAPA 2: Executar backup dos equipamentos
log_message "💾 ETAPA 2: Executando backup dos equipamentos..."

python easy-bkp-simplified.py >> "$LOG_FILE" 2>&1
BACKUP_EXIT_CODE=$?

if [ $BACKUP_EXIT_CODE -eq 0 ]; then
    log_message "✅ Backup executado com sucesso"
    
    # Encontrar o diretório de backup mais recente
    BACKUP_DIR=$(ls -1d backup_* 2>/dev/null | tail -1)
    
    if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
        log_message "📁 Diretório de backup encontrado: $BACKUP_DIR"
        
        # Contar arquivos JSON no backup
        JSON_COUNT=$(find "$BACKUP_DIR" -name "*.json" | wc -l)
        log_message "📄 Arquivos JSON coletados: $JSON_COUNT"
        
        if [ $JSON_COUNT -gt 0 ]; then
            # ETAPA 3: Processar o backup no banco de dados
            log_message "🗄️  ETAPA 3: Processando dados no banco..."
            cd "$PROJECT_DIR" || {
                log_message "ERRO: Não foi possível acessar o diretório do projeto $PROJECT_DIR"
                exit 1
            }
            
            python manage.py process_clean_backup_directory "$SCRIPT_DIR/$BACKUP_DIR" >> "$LOG_FILE" 2>&1
            PROCESS_EXIT_CODE=$?
            
            if [ $PROCESS_EXIT_CODE -eq 0 ]; then
                log_message "✅ Dados processados e salvos no banco com sucesso"
                log_message "🎉 PROCESSO COMPLETO FINALIZADO COM SUCESSO!"
            else
                log_message "❌ Erro ao processar dados no banco (código: $PROCESS_EXIT_CODE)"
            fi
        else
            log_message "⚠️ Nenhum arquivo JSON foi coletado no backup"
        fi
    else
        log_message "❌ Diretório de backup não encontrado"
    fi
else
    log_message "❌ Erro na execução do backup (código: $BACKUP_EXIT_CODE)"
fi

log_message "=== SCAN + BACKUP AUTOMATIZADO FINALIZADO ==="
echo ""