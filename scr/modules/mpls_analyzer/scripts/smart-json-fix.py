#!/usr/bin/env python3
"""
Script inteligente de correção JSON que resolve vírgulas trailing
Não requer credenciais pois trabalha com dados já coletados
"""

import os
import json
import re
from datetime import datetime

# Lista de equipamentos que falharam
FAILED_DEVICES = [
    'MA-BURITI-PE01', 'PI-CAMURUPIM-PE01', 'PI-JOAQUIMPIRES-PE01', 
    'PI-MILTONBRANDAO-PE01', 'PI-PIRACURUCA-NETCOM-CE01', 
    'PI-SAOJOAOARRAIAL-IPCONNECT-CE01', 'PI-TERESINA-GTSNET-CE01', 
    'PI-TERESINA-MONAHOTEL-CE01', 'PI-TERESINA-VELOCINET-CE01'
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATE = datetime.now().strftime("%Y-%m-%d")
BACKUP_DIR = os.path.join(SCRIPT_DIR, f"backup_{DATE}")

def smart_json_fix(content, device_name):
    """Correção inteligente que evita trailing commas"""
    print(f"🧠 Aplicando correção inteligente para {device_name}")
    
    try:
        # 1. Fix authentication-order
        content = re.sub(
            r'"dmos-aaa:authentication-order":\s*"local tacacs"',
            r'"dmos-aaa:authentication-order": ["local", "tacacs"]',
            content
        )
        print(f"   ✅ Corrigido authentication-order")
        
        # 2. Fix array closures that estão incorretas
        # Pattern: } seguido por quebra de linha e nova propriedade sem vírgula
        lines = content.split('\n')
        fixed_lines = []
        
        for i, line in enumerate(lines):
            fixed_lines.append(line)
            
            # Se a linha termina com } (mas não },) 
            if line.strip().endswith('}') and not line.strip().endswith('},'):
                # Verifica as próximas linhas para decidir se adiciona vírgula
                needs_comma = False
                
                for j in range(i + 1, min(i + 3, len(lines))):  # Verifica as próximas 2 linhas
                    next_line = lines[j].strip()
                    if next_line:  # Primeira linha não vazia
                        # Se é uma nova propriedade JSON (aspas + dois pontos)
                        if next_line.startswith('"') and ':' in next_line:
                            needs_comma = True
                        # Se é fechamento de array ou objeto, NÃO adiciona vírgula
                        elif next_line.startswith(']') or next_line.startswith('}'):
                            needs_comma = False
                        break
                
                if needs_comma:
                    fixed_lines[-1] = line.rstrip() + ','
                    print(f"   🔧 Vírgula adicionada na linha {i+1}")
        
        content = '\n'.join(fixed_lines)
        
        # 2.1. Fix específico das vírgulas faltantes baseado no JSON real
        # O problema específico é: }    "seção": { sem vírgula entre elas
        content = re.sub(r'(\s*})\s*\n\s*("lacp:link-aggregation")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("router-mpls:mpls")', r'\1,\n    \2', content)  
        content = re.sub(r'(\s*})\s*\n\s*("router-dcl:multicast")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("snmp:snmp")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("stp:stp-config")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("dmos-base:config")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("dmos-base:router")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("dmos-base:ip")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("dmos-cpu-dos-protect:cpu-dos-protect")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("dmos-assistant-task:assistant-task")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("dmos-dot1q:dot1q")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("dmos-licensing-app:license")', r'\1,\n    \2', content)
        content = re.sub(r'(\s*})\s*\n\s*("dmos-rdm:remote-devices")', r'\1,\n    \2', content)
        print(f"   🔧 Aplicadas correções específicas de vírgulas entre seções")
        
        # 3. Fix vírgulas faltantes entre seções principais (baseado no JSON real)
        # Lista de seções principais que devem ter vírgula antes
        main_sections = [
            "lacp:link-aggregation",
            "router-mpls:mpls", 
            "router-dcl:multicast",
            "snmp:snmp",
            "stp:stp-config",
            "dmos-base:config",
            "dmos-base:router",
            "dmos-base:ip",
            "dmos-cpu-dos-protect:cpu-dos-protect",
            "dmos-assistant-task:assistant-task",
            "dmos-dot1q:dot1q",
            "dmos-licensing-app:license",
            "dmos-rdm:remote-devices"
        ]
        
        for section in main_sections:
            # Padrão: }    "seção": { -> },    "seção": {
            escaped_section = re.escape(section)
            pattern = rf'(\s*}}\s*)\n(\s*)("{escaped_section}":\s*[\{{[])'
            replacement = r'\1,\n\2\3'
            
            if re.search(pattern, content):
                content = re.sub(pattern, replacement, content)
                print(f"   🔧 Vírgula adicionada antes de {section}")
        
        # Fix assistant-task array closure (missing ] before next section)
        content = re.sub(
            r'(\s*}\s*,?\s*\n)(\s*)("dmos-dot1q:dot1q":\s*\{)',
            r'      }\n    ],\n\2\3',
            content
        )
        print(f"   ✅ Corrigido fechamento do array assistant-task")
        
        # Fix license array closure (missing ] before next section) 
        content = re.sub(
            r'(\s*},?\s*\n)(\s*)("dmos-rdm:remote-devices":\s*\{)',
            r'      }\n    ],\n\2\3',
            content
        )
        print(f"   ✅ Corrigido fechamento do array license")
        
        # Fix missing comma after license key value
        content = re.sub(
            r'("key":\s*"\*\*\*")\s*(\})',
            r'\1,\n      \2',
            content
        )
        print(f"   ✅ Corrigido vírgula após license key")
        
        # 4. Remove vírgulas duplas
        content = re.sub(r',,+', ',', content)
        
        # 5. Fix trailing commas e estrutura final
        # Remove vírgula antes de ]
        content = re.sub(r',(\s*\])', r'\1', content)
        # Remove vírgula antes de } quando é o último item
        content = re.sub(r',(\s*\n\s*})', r'\1', content)
        # Fix double closing braces at end
        content = re.sub(r'}\s*}\s*', r'}\n  }\n}', content)
        print(f"   ✅ Removido trailing commas e corrigido estrutura final")
        
        # 6. Teste final
        try:
            parsed = json.loads(content)
            print(f"   ✅ JSON válido após correção inteligente!")
            return parsed, content
        except json.JSONDecodeError as e:
            print(f"   ⚠️  Ainda com erro: {e}")
            print(f"   📍 Linha: {getattr(e, 'lineno', '?')}, Coluna: {getattr(e, 'colno', '?')}")
            return None, content
            
    except Exception as e:
        print(f"   ❌ Erro na correção: {e}")
        return None, content

def process_device_smart(device_name):
    """Processamento inteligente de um device"""
    print(f"\n🧠 Processamento inteligente: {device_name}")
    
    device_dir = os.path.join(BACKUP_DIR, device_name)
    raw_file = os.path.join(device_dir, "config_raw.txt")
    
    if not os.path.exists(raw_file):
        print(f"   ❌ Arquivo não encontrado: {raw_file}")
        return False
    
    # Lê conteúdo
    with open(raw_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Encontra início do JSON
    lines = content.split('\n')
    json_start = 0
    for i, line in enumerate(lines):
        if line.strip() == '============================================================':
            json_start = i + 1
            break
    
    if json_start == 0:
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                json_start = i
                break
    
    json_content = '\n'.join(lines[json_start:])
    
    # Aplica correção inteligente
    json_data, fixed_content = smart_json_fix(json_content, device_name)
    
    if json_data:
        # Salva JSON corrigido
        json_file = os.path.join(BACKUP_DIR, f"{device_name}.json")
        
        # Extrai dados se necessário
        if 'data' in json_data:
            final_data = json_data['data']
        else:
            final_data = json_data
            
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(final_data, f, indent=2, ensure_ascii=False)
        
        print(f"   ✅ SUCESSO! JSON salvo: {json_file}")
        return True
        
    else:
        print(f"   ❌ FALHA na correção inteligente")
        # Salva tentativa para debug
        debug_file = os.path.join(device_dir, "smart_attempt.json")
        with open(debug_file, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        print(f"   💾 Debug salvo: {debug_file}")
        return False

def main():
    print(f"🧠 Correção inteligente de JSON - sem trailing commas")
    print(f"📂 Diretório: {BACKUP_DIR}")
    
    success = 0
    failed = 0
    
    for device in FAILED_DEVICES:
        if process_device_smart(device):
            success += 1
        else:
            failed += 1
    
    print(f"\n📊 Resultado da correção inteligente:")
    print(f"   ✅ Corrigidos com sucesso: {success}")
    print(f"   ❌ Ainda com problemas: {failed}")
    print(f"   📈 Total processado: {success + failed}")
    
    if success > 0:
        print(f"\n🎉 {success} dispositivos corrigidos com a correção inteligente!")
        print(f"📁 Total de JSONs no diretório agora: {94 + success} dispositivos")
        print(f"📊 Nova taxa de sucesso: {((94 + success) / 103) * 100:.1f}%")

if __name__ == "__main__":
    main()