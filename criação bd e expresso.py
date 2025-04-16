# -*- coding: utf-8 -*-

# === Aplicação Combinada: Inserção DB IGOV & Criação Usuários API Expresso ===
# Lê dados de CSVs e executa ações correspondentes via GUI com abas.
# ATENÇÃO: Contém credenciais de BD e API fixas no código (NÃO SEGURO!).
# Versão: 1.0 Combinada

# --- Imports ---
import requests
import json
import csv
import psycopg2
from psycopg2 import Error as DbError # Renomeia para evitar conflito
import tkinter as tk
from tkinter import ttk # Para usar Notebook (abas)
from tkinter import filedialog, messagebox, scrolledtext
import secrets
import string
import os
import logging
import threading
import queue
import sys

# --- Constantes Globais ---
LOG_FILENAME = "combined_app_log.log"

# --- Constantes: Inserção DB (IGOV Keys) ---
DB_BATCH_SIZE = 100
# DB_OUTPUT_FILENAME = "db_insert_summary.txt" # Arquivo de resumo (opcional)

# --- Constantes: Criação API (Expresso Users) ---
API_LOGIN_URL = "https://api-slim.expresso.pr.gov.br/celepar/Login"
API_CREATE_USER_URL = "https://api-slim.expresso.pr.gov.br/celepar/Admin/CreateUser"
API_ADD_GROUP_URL = "https://api-slim.expresso.pr.gov.br/celepar/Admin/AddUserToGroup"
API_LOGIN_ID = 99
API_CREATE_USER_ID = 64
API_ADD_GROUP_ID = 93
API_DEFAULT_PROFILE = "qliksense"
API_DEFAULT_DOMAIN_SUFFIX = "@nodomain.com"
API_DEFAULT_GROUPS = ["grupo-qliksense-active_directory", "grupo-qliksense-default"]
API_PASSWORD_LENGTH = 12
API_OUTPUT_CREDENTIALS_FILENAME = "user_credentials.csv" # Arquivo de saída da API

# --- Configuração do Logging (Unificada) ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - [%(funcName)s] - %(message)s') # Adicionado funcName
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - [%(funcName)s] - %(message)s')

# File Handler
file_handler = logging.FileHandler(LOG_FILENAME, encoding='utf-8', mode='a')
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)

# Console Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)

# Adiciona handlers ao logger raiz
logger = logging.getLogger()
# Remove handlers padrão se existirem para evitar duplicação
for handler in logger.handlers[:]:
    logger.removeHandler(handler)
logger.addHandler(file_handler)
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

logger.info("="*60)
logger.info("Aplicação Combinada (DB Insert & API Create) Iniciada.")
logger.info(f"Log será salvo em: {LOG_FILENAME}")
logger.info("="*60)


# --- Funções de Banco de Dados (Script 1 - IGOV Keys) ---

def db_connect(host, port, database, user, password):
    """Estabelece conexão PostgreSQL. Retorna conn ou None."""
    conn = None
    conn_string = f"host='{host}' port='{port}' dbname='{database}' user='{user}'"
    logger.info(f"Tentando conectar ao BD: {conn_string} password=***")
    try:
        conn = psycopg2.connect(
            host=host, port=port, database=database, user=user, password=password, connect_timeout=10
        )
        conn.autocommit = False
        logger.info(f"Conexão BD '{database}' estabelecida.")
        return conn
    except DbError as e:
        logger.error(f"Erro ao conectar ao BD: {e}", exc_info=False)
        logger.debug("Detalhes erro conexão BD:", exc_info=True)
        return None
    except Exception as e:
        logger.exception("Erro inesperado conexão BD.")
        return None

def db_close_connection(conn):
    """Fecha conexão PostgreSQL."""
    if conn and not conn.closed:
        try:
            conn.close()
            logger.info("Conexão BD fechada.")
        except Exception as e:
            logger.exception("Erro ao fechar conexão BD.")

def db_insert_batch(conn, data_batch):
    """(Helper) Insere lote na tabela indicadores.tb_chave. Retorna True/False."""
    if not data_batch: return True
    query = """
        INSERT INTO indicadores.tb_chave(nome, situacao, orgao, dt_criacao, dt_desativada,
        excluido, chave_politica, cod_orgao)
        VALUES (%s, 'Ativa', %s, Now(), null, 'N', %s, null);
    """
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.executemany(query, data_batch)
        logger.debug(f"Executemany BD com {len(data_batch)} registros OK.")
        return True
    except DbError as e:
        logger.error(f"Erro BD ao executar inserção em lote: {e}")
        if data_batch: logger.debug(f"Primeiro item lote BD com erro: {data_batch[0]}")
        return False
    except Exception as e:
        logger.exception("Erro inesperado durante db_insert_batch.")
        return False
    finally:
        if cursor:
            try: cursor.close()
            except Exception as e_cur: logger.error(f"Erro ao fechar cursor BD: {e_cur}")

def db_process_csv_and_insert(conn, csv_filepath):
    """Lê CSV, valida, chama inserção em lote para chaves IGOV. Retorna (success, error, total)."""
    batch_data = []
    processed_count, success_count, error_count = 0, 0, 0
    file_encoding = None
    encodings_to_try = ['utf-8-sig', 'utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
    logger.info(f"DB Insert: Tentando detectar encoding CSV: {csv_filepath}")
    for enc in encodings_to_try:
        try:
            with open(csv_filepath, 'r', newline='', encoding=enc) as f: f.read(1024)
            file_encoding = enc
            logger.info(f"DB Insert: Detectado encoding '{enc}'.")
            break
        except: continue
    if not file_encoding:
        logger.error(f"DB Insert: Encoding não detectado/suportado para {csv_filepath}")
        raise ValueError(f"Encoding não suportado: {os.path.basename(csv_filepath)}")

    logger.info(f"DB Insert: Lendo CSV '{os.path.basename(csv_filepath)}' (Enc: {file_encoding}).")
    try:
        with open(csv_filepath, 'r', newline='', encoding=file_encoding) as csvfile:
            reader = csv.DictReader(csvfile)
            if not reader.fieldnames: raise ValueError("CSV vazio ou sem cabeçalho.")
            required_cols = {'nome', 'orgao', 'chave_politica'}
            actual_cols_lower = set(map(str.lower, reader.fieldnames))
            if not required_cols.issubset(actual_cols_lower):
                raise ValueError(f"Colunas CSV obrigatórias não encontradas ({required_cols}). Encontradas: {reader.fieldnames}")
            logger.info(f"DB Insert: Cabeçalhos CSV OK: {reader.fieldnames}")

            for i, row in enumerate(reader):
                processed_count += 1
                line_num = i + 2
                row_lower = {k.lower(): v for k, v in row.items()}
                nome = row_lower.get('nome', '').strip()
                orgao = row_lower.get('orgao', '').strip()
                politica = row_lower.get('chave_politica', '').strip().upper()

                if not nome or not orgao or not politica:
                    logger.warning(f"DB Insert: Linha {line_num} dados incompletos. Pulando.")
                    error_count += 1; continue
                if politica not in ('S', 'N'):
                    logger.warning(f"DB Insert: Linha {line_num} 'chave_politica' inválida ('{politica}'). Pulando.")
                    error_count += 1; continue

                batch_data.append((nome, orgao, politica))
                logger.debug(f"DB Insert: Linha {line_num} adicionada ao lote.")

                if len(batch_data) >= DB_BATCH_SIZE:
                    logger.info(f"DB Insert: Inserindo lote de {len(batch_data)}...")
                    if db_insert_batch(conn, batch_data):
                        conn.commit(); logger.info("DB Insert: Lote inserido e commit OK.")
                        success_count += len(batch_data)
                    else:
                        conn.rollback(); logger.error("DB Insert: Erro no lote, rollback OK.")
                        error_count += len(batch_data)
                    batch_data.clear()

            if batch_data: # Lote final
                logger.info(f"DB Insert: Inserindo lote final de {len(batch_data)}...")
                if db_insert_batch(conn, batch_data):
                    conn.commit(); logger.info("DB Insert: Lote final inserido e commit OK.")
                    success_count += len(batch_data)
                else:
                    conn.rollback(); logger.error("DB Insert: Erro no lote final, rollback OK.")
                    error_count += len(batch_data)
                batch_data.clear()

    except FileNotFoundError: logger.error(f"DB Insert: Arquivo CSV não encontrado: {csv_filepath}"); raise
    except ValueError as ve: logger.error(f"DB Insert: Erro de validação: {ve}"); raise
    except Exception as e:
        logger.exception("DB Insert: Erro inesperado no processamento CSV/DB.")
        try: conn.rollback(); logger.info("DB Insert: Rollback devido a erro inesperado.")
        except Exception as rb_err: logger.error(f"DB Insert: Erro no rollback pós-erro: {rb_err}")
        raise

    logger.info(f"DB Insert: Processamento concluído. Total={processed_count}, Sucesso={success_count}, Falhas={error_count}")
    return success_count, error_count, processed_count


# --- Funções da API (Script 2 - Expresso Users) ---

def api_perform_login():
    """Realiza login na API Expresso. Retorna auth_token ou None."""
    # ####################################################################
    # !! ALERTA DE SEGURANÇA !! Credenciais API fixas !! NÃO SEGURO !!
    # ####################################################################
    payload = { "id": API_LOGIN_ID, "params": { "user": "*", "password": "*" } } # INSEGURO
    headers = {"Content-Type": "application/json"}
    url = API_LOGIN_URL
    try:
        logger.info(f"API Login: Tentando login em {url}...")
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
        response.raise_for_status()
        logger.info("API Login: Resposta recebida OK.")
        data = response.json()
        auth_token = None
        if isinstance(data, dict):
             auth_token = data.get("auth") or \
                          (data.get("result", {}).get("auth") if isinstance(data.get("result"), dict) else None) or \
                          (data.get("data", {}).get("auth") if isinstance(data.get("data"), dict) else None) or \
                          data.get("token")
        if auth_token:
            logger.info("API Login: Sucesso, token extraído.")
            return str(auth_token)
        else:
            logger.error(f"API Login: Chave 'auth' não encontrada na resposta: {data}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"API Login: Erro na requisição ({url}): {e}")
        if e.response is not None: logger.error(f"API Login: Resposta erro: Status={e.response.status_code}, Body={e.response.text}")
        return None
    except json.JSONDecodeError as e:
        resp_text = response.text if 'response' in locals() else 'N/A'
        logger.error(f"API Login: Erro JSON ({url}): {e}. Resposta: {resp_text}")
        return None
    except Exception as e:
        logger.exception("API Login: Erro inesperado.")
        return None

def api_create_user(user_data):
    """Cria usuário via API Expresso. Retorna resposta JSON ou None."""
    payload = { "id": API_CREATE_USER_ID, "params": user_data }
    headers = {"Content-Type": "application/json"}
    url = API_CREATE_USER_URL
    email_log = user_data.get('accountEmail', user_data.get('accountLogin', 'N/A'))
    try:
        logger.info(f"API Create User: Tentando criar usuário {email_log} em {url}...")
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=45)
        response.raise_for_status()
        logger.info(f"API Create User: Resposta recebida OK para {email_log}.")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"API Create User: Erro na requisição ({email_log}, {url}): {e}")
        if e.response is not None: logger.error(f"API Create User: Resposta erro: Status={e.response.status_code}, Body={e.response.text}")
        return None
    except json.JSONDecodeError as e:
        resp_text = response.text if 'response' in locals() else 'N/A'
        logger.error(f"API Create User: Erro JSON ({email_log}, {url}): {e}. Resposta: {resp_text}")
        return None
    except Exception as e:
        logger.exception(f"API Create User: Erro inesperado ({email_log}).")
        return None

def api_add_user_to_group(auth_token, user_identifier, group_name):
    """Adiciona usuário a grupo via API Expresso. Retorna resposta JSON ou None."""
    payload = { "id": API_ADD_GROUP_ID, "params": { "auth": auth_token, "uids": user_identifier, "cns": group_name } }
    headers = {"Content-Type": "application/json"}
    url = API_ADD_GROUP_URL
    try:
        logger.info(f"API Add Group: Tentando adicionar ID '{user_identifier}' ao grupo '{group_name}' em {url}...")
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
        response.raise_for_status()
        logger.info(f"API Add Group: Resposta recebida OK para ID '{user_identifier}' -> Grupo '{group_name}'.")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"API Add Group: Erro na requisição (ID '{user_identifier}' -> Grupo '{group_name}', {url}): {e}")
        if e.response is not None: logger.error(f"API Add Group: Resposta erro: Status={e.response.status_code}, Body={e.response.text}")
        return None
    except json.JSONDecodeError as e:
        resp_text = response.text if 'response' in locals() else 'N/A'
        logger.error(f"API Add Group: Erro JSON (ID '{user_identifier}' -> Grupo '{group_name}', {url}): {e}. Resposta: {resp_text}")
        return None
    except Exception as e:
        logger.exception(f"API Add Group: Erro inesperado (ID '{user_identifier}' -> Grupo '{group_name}').")
        return None

def api_generate_random_password(length=API_PASSWORD_LENGTH):
    """Gera senha segura (>=2 dígitos). Lança ValueError se falhar."""
    characters = string.ascii_letters + string.digits + string.punctuation
    logger.debug(f"Gerando senha com {length} caracteres...")
    attempts, max_attempts = 0, 100
    while attempts < max_attempts:
        attempts += 1
        password = ''.join(secrets.choice(characters) for _ in range(length))
        digit_count = sum(1 for c in password if c.isdigit())
        if (any(c.islower() for c in password) and any(c.isupper() for c in password)
                and digit_count >= 2 and any(c in string.punctuation for c in password)):
            logger.info(f"Senha gerada OK em {attempts} tentativa(s).")
            return password
    logger.error(f"Falha ao gerar senha após {max_attempts} tentativas.")
    raise ValueError(f"Não foi possível gerar senha válida após {max_attempts} tentativas.")

def api_create_users_from_csv(csv_filepath):
    """Lê CSV, cria usuários via API Expresso, adiciona a grupos. Retorna (success, error, total)."""
    user_credentials = []
    processed_count, success_count, error_count = 0, 0, 0
    auth_token = api_perform_login()
    if not auth_token:
        logger.error("API Create: Falha no login API. Abortando.")
        # Mensagem de erro será mostrada pela thread wrapper
        raise ConnectionError("Falha ao autenticar na API Expresso.")

    logger.info(f"API Create: Token API obtido. Processando CSV: {csv_filepath}")
    file_encoding = None
    encodings_to_try = ['utf-8-sig', 'utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
    for enc in encodings_to_try:
        try:
            with open(csv_filepath, 'r', newline='', encoding=enc) as f: csv.DictReader(f).fieldnames
            file_encoding = enc; logger.info(f"API Create: Detectado encoding '{enc}'."); break
        except: continue
    if not file_encoding:
        logger.error(f"API Create: Encoding não detectado/suportado: {csv_filepath}")
        raise ValueError(f"Encoding não suportado: {os.path.basename(csv_filepath)}")

    logger.info(f"API Create: Lendo CSV '{os.path.basename(csv_filepath)}' (Enc: {file_encoding}).")
    try:
        with open(csv_filepath, 'r', newline='', encoding=file_encoding) as csvfile:
            reader = csv.DictReader(csvfile)
            if not reader.fieldnames: raise ValueError("CSV vazio ou sem cabeçalho.")
            required_cols = {'login', 'name'}
            actual_cols_lower = set(map(str.lower, reader.fieldnames))
            if not required_cols.issubset(actual_cols_lower):
                raise ValueError(f"Colunas CSV obrigatórias não encontradas ({required_cols}). Encontradas: {reader.fieldnames}")
            logger.info(f"API Create: Cabeçalhos CSV OK: {reader.fieldnames}")

            for i, row in enumerate(reader):
                processed_count += 1
                line_num = i + 2
                row_lower = {k.lower(): v for k, v in row.items()}
                accountLogin = row_lower.get('login', '').strip() # Login original CSV
                name = row_lower.get('name', '').strip()

                logger.debug(f"API Create: Processando linha {line_num}: login='{accountLogin}', name='{name}'")
                if not accountLogin or not name:
                    logger.warning(f"API Create: Linha {line_num} dados incompletos. Pulando.")
                    error_count += 1; continue

                accountEmail = f"{accountLogin}{API_DEFAULT_DOMAIN_SUFFIX}" if "@" not in accountLogin else accountLogin
                logger.debug(f"API Create: Linha {line_num} Email formatado: {accountEmail}")
                user_id_for_groups = accountLogin # Usar login original para grupos

                try: password = api_generate_random_password()
                except ValueError as pass_err:
                    logger.error(f"API Create: Linha {line_num} erro ao gerar senha para '{accountLogin}': {pass_err}. Pulando.")
                    error_count += 1; continue

                # Payload para criar usuário (chave 'accountLogin' para email, 'accountName' para nome)
                user_info = {
                    "auth": auth_token, "accountEmail": accountEmail, "accountLogin": accountLogin, "accountName": name,
                    "accountProfile": API_DEFAULT_PROFILE, "accountPassword": password
                }
                # Se API exigir accountEmail E accountLogin:
                # user_info["accountEmail"] = accountEmail

                logger.info(f"API Create: Linha {line_num} tentando criar user '{accountEmail}' (Name: '{name}')...")
                api_response_create = api_create_user(user_info)

                if api_response_create and isinstance(api_response_create, dict) and 'error' not in api_response_create:
                    logger.info(f"API Create: Linha {line_num} user '{accountEmail}' criado OK.")
                    group_errors = 0
                    logger.info(f"API Create: Linha {line_num} adicionando ID '{user_id_for_groups}' aos grupos: {API_DEFAULT_GROUPS}...")
                    for group in API_DEFAULT_GROUPS:
                        api_response_group = api_add_user_to_group(auth_token, user_id_for_groups, group)
                        if api_response_group and isinstance(api_response_group, dict) and 'error' not in api_response_group:
                            logger.info(f"API Create: Linha {line_num} ID '{user_id_for_groups}' adicionado OK ao grupo '{group}'.")
                        else:
                            logger.warning(f"API Create: Linha {line_num} falha ao adicionar ID '{user_id_for_groups}' ao grupo '{group}'. Resposta: {api_response_group}")
                            group_errors += 1
                    if group_errors == 0:
                        user_credentials.append({"login": accountEmail, "password": password})
                        success_count += 1
                    else:
                        logger.warning(f"API Create: Linha {line_num} user '{accountEmail}' criado, mas com {group_errors} erro(s) nos grupos.")
                        user_credentials.append({"login": accountEmail, "password": f"{password} [ERRO NOS GRUPOS]"})
                        error_count += 1
                else:
                    error_detail = api_response_create.get('error', {}).get('message', str(api_response_create)) if isinstance(api_response_create, dict) else str(api_response_create)
                    logger.error(f"API Create: Linha {line_num} falha ao criar user '{accountEmail}'. Detalhe API: {error_detail}")
                    error_count += 1

        logger.info(f"API Create: Processamento CSV concluído. Total={processed_count}, Sucesso={success_count}, Falhas={error_count}")

        # Gerar CSV de credenciais se houver sucessos
        if user_credentials:
            output_dir = os.path.dirname(csv_filepath)
            output_filepath = os.path.join(output_dir, API_OUTPUT_CREDENTIALS_FILENAME)
            try:
                with open(output_filepath, 'w', newline='', encoding='utf-8') as outfile:
                    writer = csv.DictWriter(outfile, fieldnames=["login", "password"])
                    writer.writeheader(); writer.writerows(user_credentials)
                logger.info(f"API Create: Arquivo de credenciais gerado: {output_filepath}")
                # Aviso de segurança será mostrado pela thread wrapper
            except IOError as e:
                logger.exception(f"API Create: Erro ao escrever CSV de credenciais: {e}")
                # Não levantar erro aqui, apenas logar, pois a operação principal pode ter tido sucesso.

    except FileNotFoundError: logger.error(f"API Create: Arquivo CSV não encontrado: {csv_filepath}"); raise
    except ValueError as ve: logger.error(f"API Create: Erro de validação: {ve}"); raise
    except Exception as e: logger.exception("API Create: Erro inesperado no processamento CSV/API."); raise

    return success_count, error_count, processed_count


# --- Funções e Classes da Interface Gráfica (Compartilhadas) ---

def browse_file(entry_widget, info_title="Formato Esperado", info_message="Verifique as colunas necessárias para esta operação."):
    """Abre diálogo para selecionar arquivo CSV e atualiza o campo de entrada."""
    messagebox.showinfo(info_title, info_message)
    filename = filedialog.askopenfilename(
        title="Selecione o arquivo CSV", filetypes=[("Arquivos CSV", "*.csv"), ("Todos os arquivos", "*.*")]
    )
    if filename:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)
        logger.info(f"Arquivo CSV selecionado: {filename}")

class QueueHandler(logging.Handler):
    """Envia logs para uma fila da GUI."""
    def __init__(self, log_queue): super().__init__(); self.log_queue = log_queue
    def emit(self, record):
        msg = self.format(record)
        try: self.log_queue.put_nowait(msg)
        except queue.Full: print(f"ALERTA: Fila log GUI cheia: {msg}")

class TkinterLogDisplay:
    """Exibe logs de uma fila em um widget Text."""
    POLL_INTERVAL = 150
    def __init__(self, text_widget):
        self.text_widget = text_widget; self.log_queue = queue.Queue()
        self.queue_handler = QueueHandler(self.log_queue); self.is_polling = False
        self.queue_handler.setLevel(logging.DEBUG) # GUI pode mostrar mais detalhes
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
        self.queue_handler.setFormatter(formatter)
        logging.getLogger().addHandler(self.queue_handler)
        self.start_polling()
    def display(self, record_str):
        state = self.text_widget['state']
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, record_str + '\n')
        self.text_widget.configure(state=state)
        if self.text_widget.yview()[1] > 0.99: self.text_widget.yview(tk.END)
    def poll_log_queue(self):
        while True:
            try: record = self.log_queue.get(block=False)
            except queue.Empty: break
            else: self.display(record)
        if self.is_polling: self.text_widget.after(self.POLL_INTERVAL, self.poll_log_queue)
    def start_polling(self):
        if not self.is_polling: self.is_polling = True; self.text_widget.after(self.POLL_INTERVAL, self.poll_log_queue)
    def stop_polling(self): self.is_polling = False


# --- Wrappers de Thread e Funções de Início (Específicos) ---

def run_db_insert_thread_wrapper(csv_filepath, run_button, browse_button, root):
    """Wrapper para executar a inserção DB em uma thread."""
    root.after(0, lambda: run_button.config(state=tk.DISABLED))
    root.after(0, lambda: browse_button.config(state=tk.DISABLED))
    logger.info(f"DB Insert Thread: Iniciando para {csv_filepath}...")
    conn = None; success, errors, total = 0, 0, 0
    final_message = "DB Insert: Processo finalizado."; msg_type = "info"
    try:
        # ######################################################
        # !! ALERTA DE SEGURANÇA !! Credenciais BD fixas !!
        # ######################################################
        host = "*"; port = "*"; database = "*"; user = "*"; password = "*" # INSEGURO
        conn = db_connect(host, port, database, user, password)
        if conn:
            success, errors, total = db_process_csv_and_insert(conn, csv_filepath)
            final_message = f"Inserção BD Concluída.\n\nArquivo: {os.path.basename(csv_filepath)}\nLinhas Processadas: {total}\nSucessos: {success}\nFalhas: {errors}\n\nLog: {LOG_FILENAME}"
            if errors > 0: msg_type = "warning"
        else:
            final_message = "Erro Crítico: Falha na conexão com o BD."; msg_type = "error"
    except Exception as e:
        logger.exception("DB Insert Thread: Erro crítico não capturado.")
        final_message = f"Erro Crítico na Thread DB:\n{e}\n\nLog: {LOG_FILENAME}."; msg_type = "error"
    finally:
        if conn: db_close_connection(conn)
        root.after(0, lambda: run_button.config(state=tk.NORMAL))
        root.after(0, lambda: browse_button.config(state=tk.NORMAL))
        logger.info("DB Insert Thread: Finalizada.")
        if msg_type == "info": root.after(0, lambda: messagebox.showinfo("DB Concluído", final_message))
        elif msg_type == "warning": root.after(0, lambda: messagebox.showwarning("DB Concluído com Avisos", final_message))
        else: root.after(0, lambda: messagebox.showerror("DB Erro Crítico", final_message))

def start_db_insert_script(csv_entry, run_button, browse_button, root):
    """Verifica CSV e inicia a thread de inserção DB."""
    csv_filepath = csv_entry.get().strip()
    if not csv_filepath or not os.path.isfile(csv_filepath):
        messagebox.showerror("Erro", f"Arquivo CSV inválido ou não encontrado:\n{csv_filepath}")
        return
    thread = threading.Thread(target=run_db_insert_thread_wrapper, args=(csv_filepath, run_button, browse_button, root), name="DBInsertThread", daemon=True)
    thread.start()


def run_api_creation_thread_wrapper(csv_filepath, run_button, browse_button, root):
    """Wrapper para executar a criação API em uma thread."""
    root.after(0, lambda: run_button.config(state=tk.DISABLED))
    root.after(0, lambda: browse_button.config(state=tk.DISABLED))
    logger.info(f"API Create Thread: Iniciando para {csv_filepath}...")
    success, errors, total = 0, 0, 0
    final_message = "API Create: Processo finalizado."; msg_type = "info"
    credentials_generated = False
    try:
        success, errors, total = api_create_users_from_csv(csv_filepath)
        output_csv_path = os.path.join(os.path.dirname(csv_filepath), API_OUTPUT_CREDENTIALS_FILENAME)
        credentials_generated = success > 0 or (errors > 0 and "[ERRO NOS GRUPOS]" in open(output_csv_path).read()) # Checa se arquivo foi gerado
        final_message = f"Criação API Concluída.\n\nArquivo: {os.path.basename(csv_filepath)}\nLinhas Processadas: {total}\nSucessos: {success}\nFalhas/Parciais: {errors}\n\nLog: {LOG_FILENAME}"
        if credentials_generated:
             final_message += f"\n\nArquivo de credenciais gerado:\n{output_csv_path}"
        if errors > 0: msg_type = "warning"
    except Exception as e:
        logger.exception("API Create Thread: Erro crítico não capturado.")
        final_message = f"Erro Crítico na Thread API:\n{e}\n\nLog: {LOG_FILENAME}."; msg_type = "error"
    finally:
        root.after(0, lambda: run_button.config(state=tk.NORMAL))
        root.after(0, lambda: browse_button.config(state=tk.NORMAL))
        logger.info("API Create Thread: Finalizada.")
        if msg_type == "info": root.after(0, lambda: messagebox.showinfo("API Concluído", final_message))
        elif msg_type == "warning": root.after(0, lambda: messagebox.showwarning("API Concluído com Avisos", final_message))
        else: root.after(0, lambda: messagebox.showerror("API Erro Crítico", final_message))
        # Adiciona o alerta de segurança do CSV de senhas se ele foi gerado
        if credentials_generated and msg_type != "error":
             root.after(100, lambda: messagebox.showwarning("API - Atenção à Segurança!", f"O arquivo '{API_OUTPUT_CREDENTIALS_FILENAME}' contém senhas!\nManuseie com segurança e exclua quando não for mais necessário."))


def start_api_creation_script(csv_entry, run_button, browse_button, root):
    """Verifica CSV e inicia a thread de criação API."""
    csv_filepath = csv_entry.get().strip()
    if not csv_filepath or not os.path.isfile(csv_filepath):
        messagebox.showerror("Erro", f"Arquivo CSV inválido ou não encontrado:\n{csv_filepath}")
        return
    thread = threading.Thread(target=run_api_creation_thread_wrapper, args=(csv_filepath, run_button, browse_button, root), name="APICreateThread", daemon=True)
    thread.start()


# --- Montagem da Interface Gráfica (com Abas) ---
def setup_gui():
    root = tk.Tk()
    root.title("Ferramenta IGOV/Expresso v1.0")
    root.minsize(750, 550)

    main_frame = tk.Frame(root, padx=10, pady=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # --- Notebook (Abas) ---
    notebook = ttk.Notebook(main_frame)
    notebook.pack(pady=10, padx=5, fill=tk.X, expand=False) # Notebook não expande verticalmente

    # --- Aba 1: Inserção DB (Chaves IGOV) ---
    db_tab = ttk.Frame(notebook, padding="10")
    notebook.add(db_tab, text=' Inserir Chaves BD (IGOV) ')

    db_file_frame = tk.Frame(db_tab)
    db_file_frame.pack(fill=tk.X, pady=(5, 10))
    db_csv_label = tk.Label(db_file_frame, text="Arquivo CSV Chaves:")
    db_csv_label.pack(side=tk.LEFT, padx=(0, 5))
    db_csv_entry = tk.Entry(db_file_frame, width=55)
    db_csv_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    db_browse_button = tk.Button(db_file_frame, text="Procurar...",
                                 command=lambda: browse_file(db_csv_entry,
                                                             "CSV Chaves IGOV",
                                                             "Colunas esperadas: nome, orgao, chave_politica ('S' ou 'N')"))
    db_browse_button.pack(side=tk.LEFT, padx=(5, 0))

    db_run_button = tk.Button(db_tab, text="Executar Inserção no Banco de Dados", font=('Segoe UI', 10, 'bold'), height=2, relief=tk.RAISED)
    db_run_button.pack(fill=tk.X, pady=(5, 10))
    db_run_button.config(command=lambda: start_db_insert_script(db_csv_entry, db_run_button, db_browse_button, root))

    # --- Aba 2: Criação API (Usuários Expresso) ---
    api_tab = ttk.Frame(notebook, padding="10")
    notebook.add(api_tab, text=' Criar Usuários API (Expresso) ')

    api_file_frame = tk.Frame(api_tab)
    api_file_frame.pack(fill=tk.X, pady=(5, 10))
    api_csv_label = tk.Label(api_file_frame, text="Arquivo CSV Usuários:")
    api_csv_label.pack(side=tk.LEFT, padx=(0, 5))
    api_csv_entry = tk.Entry(api_file_frame, width=55)
    api_csv_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    api_browse_button = tk.Button(api_file_frame, text="Procurar...",
                                  command=lambda: browse_file(api_csv_entry,
                                                              "CSV Usuários Expresso",
                                                              "Colunas esperadas: login, name"))
    api_browse_button.pack(side=tk.LEFT, padx=(5, 0))

    api_run_button = tk.Button(api_tab, text="Executar Criação de Usuários via API", font=('Segoe UI', 10, 'bold'), height=2, relief=tk.RAISED)
    api_run_button.pack(fill=tk.X, pady=(5, 10))
    api_run_button.config(command=lambda: start_api_creation_script(api_csv_entry, api_run_button, api_browse_button, root))


    # --- Área de Log (Compartilhada Fora das Abas) ---
    log_frame = tk.LabelFrame(main_frame, text="Log da Execução", padx=5, pady=5)
    log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(10, 5))

    log_text_widget = scrolledtext.ScrolledText(log_frame, state='disabled', height=15, wrap=tk.WORD, font=('Consolas', 9))
    log_text_widget.pack(fill=tk.BOTH, expand=True)

    # Configura o display de log da GUI (instância precisa ser mantida)
    log_display_instance = TkinterLogDisplay(log_text_widget)

    # --- Tratamento de Fechamento da Janela ---
    def on_closing():
        logger.info("Janela fechada pelo usuário.")
        if log_display_instance: log_display_instance.stop_polling()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_closing)

    # --- Iniciar GUI ---
    logger.info("Interface gráfica combinada configurada e pronta.")
    root.mainloop()
    logger.info("Aplicação finalizada.")
    logger.info("="*60 + "\n")

# --- Ponto de Entrada Principal ---
if __name__ == "__main__":
    # Handler opcional para exceções não capturadas
    def handle_exception(exc_type, exc_value, exc_traceback):
        logger.error("Erro não capturado globalmente:", exc_info=(exc_type, exc_value, exc_traceback))
        try: messagebox.showerror("Erro Fatal Inesperado", f"Ocorreu um erro não tratado:\n{exc_value}\nO programa pode precisar ser fechado.\nVerifique o log '{LOG_FILENAME}'.")
        except Exception: pass
    sys.excepthook = handle_exception

    setup_gui() # Inicia a aplicação