import paramiko
import json
import os
from datetime import datetime
import re

# Configurações SSH
USERNAME = os.environ.get("DEVICE_USERNAME", "corewise")  # Nome de usuário via env ou padrão
PASSWORD = os.environ.get("DEVICE_PASSWORD", "T@yr0narj123")  # Senha via env ou padrão
SSH_PORT = 5620  # Porta SSH

# Comando essencial - apenas configuração principal
COMMAND = {
    "command": "show running-config | display json | nomore",
    "description": "Configuração principal do equipamento",
    "timeout": 60  # Timeout aumentado para configs grandes
}

# Nome do arquivo JSON com os dispositivos (pode ser sobrescrito por DEVICES_JSON)
JSON_FILE = os.environ.get("DEVICES_JSON", "banco-de-dados.json")

# Diretório do script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Diretório de backup com data
DATE = datetime.now().strftime("%Y-%m-%d")
BACKUP_DIR = os.path.join(SCRIPT_DIR, f"backup_{DATE}")
os.makedirs(BACKUP_DIR, exist_ok=True)  # Cria a pasta se não existir

# Função para carregar dispositivos do JSON
def load_devices_from_json(json_file):
    try:
        json_path = os.path.join(SCRIPT_DIR, json_file)  # Garante que o JSON esteja no mesmo local do script
        if not os.path.exists(json_path):
            print(f"Arquivo JSON {json_path} não encontrado.")
            return []
        with open(json_path, "r", encoding="utf-8") as file:
            devices = json.load(file)
            print(f"{len(devices)} dispositivos carregados do arquivo {json_path}.")
            return devices
    except json.JSONDecodeError as e:
        print(f"Erro ao ler o arquivo JSON {json_file}: {e}")
        return []

def validate_and_clean_json(raw_output, device_name):
    """Valida, tenta corrigir e retorna (json_dict, json_string_corrigido)."""
    print(f"    🔍 DEBUG: Analisando output de {device_name}...")
    print(f"    📏 Tamanho total da saída: {len(raw_output)} caracteres")
    
    try:
        json_content = ""
        # Remove linhas extras antes e depois do JSON
        lines = raw_output.strip().split('\n')
        print(f"    📄 Total de linhas: {len(lines)}")
        
        # Mostra as primeiras e últimas linhas para debug
        print(f"    🔝 Primeiras 3 linhas:")
        for i, line in enumerate(lines[:3]):
            print(f"      {i+1:3d}: {repr(line[:100])}")
        
        print(f"    🔚 Últimas 3 linhas:")
        for i, line in enumerate(lines[-3:]):
            line_num = len(lines) - 3 + i + 1
            print(f"      {line_num:3d}: {repr(line[:100])}")
        
        json_start = -1
        json_end = -1
        
        # Encontra início do JSON
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                json_start = i
                print(f"    🎯 JSON inicia na linha {i+1}")
                break
        
        if json_start == -1:
            print(f"    ❌ JSON não encontrado na saída")
            return None
        
        # Encontra fim do JSON (conta chaves para garantir JSON completo)
        brace_count = 0
        max_depth = 0
        
        for i in range(json_start, len(lines)):
            line = lines[i]
            line_braces_open = line.count('{')
            line_braces_close = line.count('}')
            
            brace_count += line_braces_open
            brace_count -= line_braces_close
            
            if brace_count > max_depth:
                max_depth = brace_count
            
            # Debug a cada 100 linhas ou quando chaves mudam significativamente
            if i % 100 == 0 or line_braces_open > 0 or line_braces_close > 0:
                if i % 100 == 0 or brace_count <= 5:  # Só mostra quando perto do fim
                    print(f"    📊 Linha {i+1}: braces={brace_count} (max={max_depth})")
            
            if brace_count == 0 and i > json_start:
                json_end = i
                print(f"    🏁 JSON termina na linha {i+1}")
                break
        
        if json_end == -1:
            print(f"    ⚠️  JSON incompleto - brace_count final: {brace_count}, max_depth: {max_depth}")
            print(f"    📊 Analisando truncamento...")
            
            # Verifica se a saída foi truncada
            last_lines = lines[-5:]
            for i, line in enumerate(last_lines):
                print(f"    📝 Linha {len(lines)-5+i+1}: {repr(line)}")
            
            # Tenta salvar o que temos mesmo que incompleto
            json_content = '\n'.join(lines[json_start:])
            
            # Tenta consertar fechando chaves em falta
            missing_braces = brace_count
            if missing_braces > 0:
                print(f"    🔧 Tentando adicionar {missing_braces} chaves de fechamento...")
                json_content += '\n' + '}' * missing_braces
            
        else:
            # Extrai apenas o JSON válido
            json_content = '\n'.join(lines[json_start:json_end+1])
            print(f"    ✅ JSON extraído: {json_end-json_start+1} linhas")
        
        # Correções específicas para problemas comuns
        try:
            # 1. Corrige authentication-order que deve ser array mas vem como string
            json_content = re.sub(
                r'"dmos-aaa:authentication-order":\s*"([^"]+)"',
                r'"dmos-aaa:authentication-order": ["\1"]',
                json_content
            )
            print(f"    🔧 Corrigido: authentication-order convertido para array")
            
            # 2. Corrige strings com espaços que deveriam ser arrays
            json_content = re.sub(
                r'"dmos-aaa:authentication-order":\s*\["([^"]+)\s+([^"]+)"\]',
                r'"dmos-aaa:authentication-order": ["\1", "\2"]',
                json_content
            )
            
            # 3. Corrige objetos vazios mal formados (remove espaços em branco desnecessários)
            json_content = re.sub(r'\{\s*\n\s*\}', '{}', json_content)
            print(f"    🔧 Corrigido: objetos vazios limpos")
            
        except Exception as fix_err:
            print(f"    ⚠️  Falha ao aplicar correções específicas: {fix_err}")

        # Correção: inserir vírgulas ausentes entre chaves irmãs (ex.: '}' seguido de nova chave em nova linha)
        # Exemplo observado: '... }\n    "router-mpls:mpls": {' deveria ser '... },\n    "router-mpls:mpls": {'
        try:
            # Insere vírgula quando uma linha termina com '}', ']', '"', dígito ou fim de true/false/null
            # e a próxima linha (mesmo nível ou não) começa com uma chave de objeto '"...":'
            pattern = re.compile(r'([\}\]"0-9el])\s*\n(\s*)(?=")')
            matches = list(pattern.finditer(json_content))
            if matches:
                print(f"    🧼 Corrigindo vírgulas ausentes entre chaves adjacentes... ({len(matches)} ajustes)")
                json_content = pattern.sub(r'\1,\n\2', json_content)
        except Exception as fix_err:
            print(f"    ⚠️  Falha ao aplicar correção de vírgulas: {fix_err}")

        # Correção: se houver colchetes '[' abertos restantes e pares '}}' no final de blocos,
        # substituir '}}' por ']}' do fim para o início até equilibrar os colchetes
        try:
            open_arrays = json_content.count('[') - json_content.count(']')
            fixes_applied = 0
            while open_arrays > 0 and '}}' in json_content:
                last_idx = json_content.rfind('}}')
                if last_idx == -1:
                    break
                # Se antes de '}}' houver '"key":', assumimos bloco de license e fechamos array e objeto
                json_content = json_content[:last_idx] + '}]' + json_content[last_idx+2:]
                fixes_applied += 1
                open_arrays = json_content.count('[') - json_content.count(']')
            if fixes_applied:
                print(f"    🔧 Correção de sufixo: trocado '}}' por ']}}' {fixes_applied} vez(es)")
        except Exception as e_fix:
            print(f"    ⚠️  Falha ao equilibrar colchetes no sufixo: {e_fix}")

        print(f"    🧪 Testando parse do JSON...")
        # Testa se é JSON válido, com tentativas de correção de arrays abertos
        attempts = 0
        while True:
            try:
                parsed_json = json.loads(json_content)
                print(f"    ✅ JSON válido! Chaves principais: {list(parsed_json.keys())[:5]}")
                # Retorna também o conteúdo JSON (já possivelmente corrigido) para debug/salvamento
                return parsed_json, json_content
            except json.JSONDecodeError as e_attempt:
                attempts += 1
                if attempts > 5:
                    raise
                # Heurística: fechar array aberto antes de nova chave
                json_lines = json_content.split('\n')
                err_idx = max(0, getattr(e_attempt, 'lineno', 1) - 1)
                current_line = json_lines[err_idx] if err_idx < len(json_lines) else ""
                current_line_stripped = current_line.lstrip()
                # Só tenta se a linha problemática parece uma nova chave JSON
                if not current_line_stripped.startswith('"'):
                    # Último recurso dentro do mesmo ciclo: balancear chaves finais
                    missing_curly_inline = json_content.count('{') - json_content.count('}')
                    if 0 < missing_curly_inline <= 2:
                        json_content = json_content + ('}' * missing_curly_inline)
                        print(f"    🔧 Balanceamento final: adicionadas {missing_curly_inline} chave(s) '}}'")
                        continue
                    raise
                # Encontra linha anterior não vazia
                prev_idx = err_idx - 1
                while prev_idx >= 0 and json_lines[prev_idx].strip() == "":
                    prev_idx -= 1
                if prev_idx < 0:
                    raise
                # Calcula balanço de colchetes até a linha anterior
                prefix_text = '\n'.join(json_lines[:prev_idx + 1])
                open_arrays = prefix_text.count('[') - prefix_text.count(']')
                if open_arrays <= 0:
                    raise
                # Remove vírgula final da linha anterior se existir (evita vírgula antes de "]")
                prev_line = json_lines[prev_idx]
                if prev_line.rstrip().endswith('},'):
                    json_lines[prev_idx] = prev_line.rstrip()[:-1]  # remove a vírgula
                # Insere fechamento do array antes da linha atual
                current_indent = len(current_line) - len(current_line.lstrip(' '))
                # Se a linha seguinte for o fechamento final '}' do topo, não colocar vírgula após ']' para evitar erro
                next_line = json_lines[err_idx] if err_idx < len(json_lines) else ''
                closing_with_comma = '],'
                if next_line.strip() == '}' or next_line.strip().startswith('}'):  # fechamento final
                    closing_with_comma = ']'
                json_lines.insert(err_idx, ' ' * current_indent + closing_with_comma)
                json_content = '\n'.join(json_lines)
                print(f"    🔧 Heurística: inserido fechamento de array em linha {err_idx+1}")
                continue
            except Exception:
                # Tenta último recurso: se faltar exatamente uma '}', adicionar no final
                missing_curly = json_content.count('{') - json_content.count('}')
                if 0 < missing_curly <= 2:
                    json_content = json_content + ('}' * missing_curly)
                    print(f"    🔧 Balanceamento final: adicionadas {missing_curly} chave(s) '}}'")
                    continue
                raise
        
    except json.JSONDecodeError as e:
        print(f"    ❌ JSON inválido: {e}")
        print(f"    📍 Erro na linha {getattr(e, 'lineno', '?')}, coluna {getattr(e, 'colno', '?')}")
        
        # Mostra contexto do erro
        try:
            error_line = getattr(e, 'lineno', 0)
            if error_line > 0:
                json_lines = json_content.split('\n')
                start = max(0, error_line - 3)
                end = min(len(json_lines), error_line + 2)
                print(f"    🔍 Contexto do erro:")
                for i in range(start, end):
                    marker = " >>> " if i == error_line - 1 else "     "
                    print(f"    {marker}{i+1:4d}: {repr(json_lines[i][:100])}")
        except Exception:
            pass
            
        # Retorna o conteúdo tentado para permitir salvamento offline e inspeção
        try:
            attempted = json_content if json_content else raw_output
        except Exception:
            attempted = raw_output
        return None, attempted
    except Exception as e:
        print(f"    ❌ Erro inesperado ao processar JSON: {e}")
        return None, None

def execute_ssh_command(device):
    """Executa apenas o comando essencial de configuração"""
    try:
        print(f"🔗 Conectando ao dispositivo {device['name']} ({device['ip']})...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            device["ip"], port=SSH_PORT, username=USERNAME, password=PASSWORD, timeout=20
        )

        # Removido: criação de diretório individual (otimização de velocidade)
        # device_dir = os.path.join(BACKUP_DIR, device['name'])
        # os.makedirs(device_dir, exist_ok=True)
        
        command = COMMAND['command']
        print(f"  📡 Executando: {COMMAND['description']}")
        print(f"  🎯 Comando: {command}")
        
        try:
            # Executa comando com timeout maior
            print(f"    ⏱️  Executando comando (timeout: {COMMAND['timeout']}s)...")
            stdin, stdout, stderr = client.exec_command(command, timeout=COMMAND['timeout'])
            
            print(f"    📥 Lendo saída...")
            raw_output = stdout.read().decode("utf-8")
            stderr_output = stderr.read().decode("utf-8")
            
            if stderr_output:
                print(f"    ⚠️  Stderr: {stderr_output.strip()}")
            
            print(f"    📊 Saída capturada: {len(raw_output)} caracteres")
            
            # Removido: salvamento de raw output (otimização de velocidade)
            # raw_file = os.path.join(device_dir, "config_raw.txt")
            # print(f"    🔍 Raw output salvo: {raw_file}")
            
            # Valida e limpa JSON
            json_data, fixed_json_string = validate_and_clean_json(raw_output, device['name'])
            
            if json_data:
                # Salva apenas o arquivo JSON principal (otimização de velocidade)
                main_file = os.path.join(BACKUP_DIR, f"{device['name']}.json")
                with open(main_file, "w", encoding="utf-8") as f:
                    # Salva apenas os dados (sem metadata) para compatibilidade com parser atual
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
                print(f"    ✅ Config salvo: {main_file}")
                
                print(f"  ✅ SUCESSO: Configuração coletada e salva")
                return True
                
            else:
                print(f"  ❌ FALHA: JSON inválido ou incompleto")
                # Removido: salvamento de arquivos de debug (otimização de velocidade)
                return False
                
        except Exception as cmd_error:
            print(f"    ❌ Erro ao executar comando: {cmd_error}")
            return False
        
    except paramiko.AuthenticationException:
        print(f"❌ Falha na autenticação para {device['name']} ({device['ip']}).")
        return False
    except paramiko.SSHException as e:
        print(f"❌ Erro SSH ao conectar ao dispositivo {device['name']} ({device['ip']}): {e}")
        return False
    except Exception as e:
        print(f"❌ Erro inesperado com {device['name']} ({device['ip']}): {e}")
        return False
    finally:
        try:
            client.close()
        except Exception:
            pass
        print(f"🔌 Conexão com {device['name']} encerrada.\n")

if __name__ == "__main__":
    print(f"🚀 Iniciando backup das configurações no diretório: {BACKUP_DIR}")
    print(f"📅 Data do backup: {DATE}")
    print(f"📡 Comando: {COMMAND['command']}")
    print()
    
    devices = load_devices_from_json(JSON_FILE)
    # Filtro opcional por nome do dispositivo para testes
    device_name_filter = os.environ.get("DEVICE_NAME")
    if devices and device_name_filter:
        devices = [d for d in devices if d.get("name") == device_name_filter]
        print(f"🔎 Filtro DEVICE_NAME ativo: {device_name_filter} — {len(devices)} dispositivo(s) selecionado(s)")
    if devices:
        print(f"📋 Dispositivos carregados: {len(devices)}")
        print()
        
        successful_devices = 0
        failed_devices = 0
        
        for i, device in enumerate(devices, 1):
            print(f"📱 [{i}/{len(devices)}] Processando {device['name']}...")
            
            if execute_ssh_command(device):
                successful_devices += 1
            else:
                failed_devices += 1
        
        print("=" * 60)
        print(f"📊 RESUMO FINAL DO BACKUP:")
        print(f"   ✅ Dispositivos processados com sucesso: {successful_devices}")
        print(f"   ❌ Dispositivos com falha: {failed_devices}")
        print(f"   📁 Diretório de backup: {BACKUP_DIR}")
        print(f"   🕒 Concluído em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        if successful_devices > 0:
            print("🎯 Para processar os dados coletados:")
            print(f"   python manage.py process_clean_backup_directory {BACKUP_DIR}")
        
        print("🎉 Backup concluído!")
    else:
        print("❌ Nenhum dispositivo encontrado para realizar o backup.")