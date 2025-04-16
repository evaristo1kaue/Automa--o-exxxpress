# -*- coding: utf-8 -*-

# === Script para Criação de Usuários e Adição a Grupos via API ===
# Lê usuários de um CSV, cria na API Expresso, adiciona a grupos
# e gera um CSV com credenciais (email e senha).
# ATENÇÃO: Contém credenciais de API fixas no código (NÃO SEGURO!).
# Versão: 2.3 (Corrige geração de senha para >= 2 dígitos)

import requests
import json
import csv
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import secrets  # Para geração de senhas seguras
import string
import os
import logging # Para logging detalhado
import threading # Para não bloquear a GUI
import queue # Para comunicação segura entre thread e GUI
import sys # Para o excepthook opcional

# --- Constantes de Configuração ---
# (Idealmente, viriam de um arquivo de config ou variáveis de ambiente)

# URLs e IDs da API
API_LOGIN_URL = "https://api-slim.expresso.pr.gov.br/celepar/Login"
API_CREATE_USER_URL = "https://api-slim.expresso.pr.gov.br/celepar/Admin/CreateUser"
API_ADD_GROUP_URL = "https://api-slim.expresso.pr.gov.br/celepar/Admin/AddUserToGroup"
LOGIN_API_ID = 99
CREATE_USER_API_ID = 64
ADD_GROUP_API_ID = 93

# Configurações do Processo
DEFAULT_PROFILE = "qliksense" # Perfil padrão a ser atribuído
DEFAULT_DOMAIN_SUFFIX = "@nodomain.com" # Sufixo a ser adicionado se não houver @ no login
DEFAULT_GROUPS = ["grupo-qliksense-active_directory", "grupo-qliksense-default"] # Grupos padrão
PASSWORD_LENGTH = 12 # Comprimento da senha
OUTPUT_FILENAME = "user_credentials.csv" # Nome do arquivo de saída
LOG_FILENAME = "user_creation_log.log" # Nome do arquivo de log

# --- Configuração do Logging ---
# Configura o logging para arquivo e console
# O handler da GUI será adicionado depois que a GUI for criada
logging.basicConfig(
    level=logging.INFO, # Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILENAME, encoding='utf-8', mode='a'), # 'a' para append
        logging.StreamHandler() # Log também no console
    ]
)
logging.info("="*50)
logging.info("Aplicação iniciada.")
logging.info(f"Log será salvo em: {LOG_FILENAME}")
logging.info("="*50)


# --- Funções da API ---

def perform_login():
    """
    Realiza uma requisição de login para a API com credenciais fixas.

    Returns:
        str or None: O token 'auth' se bem-sucedido, None caso contrário.
    """
    # ####################################################################
    # !! ALERTA DE SEGURANÇA !! ALERTA DE SEGURANÇA !! ALERTA DE SEGURANÇA !!
    # As credenciais ('user', 'password') estão fixas no código abaixo.
    # ISTO NÃO É SEGURO PARA PRODUÇÃO OU AMBIENTES REAIS.
    # Modifique para usar variáveis de ambiente, cofre de segredos, etc.
    # ####################################################################
    payload = {
        "id": LOGIN_API_ID,
        "params": {
            "user": "*",  # Credencial Fixa - MUITO INSEGURO
            "password": "*"   # Credencial Fixa - MUITO INSEGURO
        }
    }
    headers = {"Content-Type": "application/json"}
    url = API_LOGIN_URL

    try:
        logging.info(f"Tentando realizar o login na API: {url}")
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30) # Timeout de 30s
        response.raise_for_status() # Verifica erros HTTP (4xx ou 5xx)
        logging.info("Resposta da API de Login recebida com sucesso.")
        # logging.debug(f"Resposta bruta login: {response.text}")

        data = response.json()

        # Extrair o token 'auth' de forma mais robusta
        auth_token = None
        if isinstance(data, dict):
            if "auth" in data:
                auth_token = data["auth"]
            elif "result" in data and isinstance(data["result"], dict) and "auth" in data["result"]:
                auth_token = data["result"]["auth"]
            elif "data" in data and isinstance(data["data"], dict) and "auth" in data["data"]:
                 auth_token = data["data"]["auth"]
            elif "token" in data:
                 auth_token = data["token"]

        if auth_token:
            logging.info("Login bem-sucedido. Token 'auth' extraído.")
            return str(auth_token)
        else:
            logging.error("A chave 'auth' (ou alternativa) não foi encontrada na resposta JSON da API de login.")
            logging.error(f"Resposta JSON recebida: {data}")
            return None

    except requests.exceptions.Timeout:
        logging.error(f"Erro durante a requisição de login ({url}): Timeout (tempo esgotado).")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro durante a requisição de login ({url}): {e}")
        if e.response is not None:
            logging.error(f"Detalhes da resposta de erro: Status={e.response.status_code}, Body={e.response.text}")
        return None
    except json.JSONDecodeError as e:
        resp_text = response.text if 'response' in locals() else 'N/A'
        logging.error(f"Erro ao decodificar JSON de login ({url}): {e}. Resposta recebida: {resp_text}")
        return None
    except Exception as e:
        logging.exception("Erro inesperado durante o login.")
        return None


def create_user(user_data):
    """
    Cria um novo usuário via API.

    Args:
        user_data (dict): Dicionário com dados do usuário (auth, accountEmail, etc.).

    Returns:
        dict or None: Resposta JSON da API ou None em caso de erro.
    """
    payload = {
        "id": CREATE_USER_API_ID,
        "params": user_data
    }
    headers = {"Content-Type": "application/json"}
    url = API_CREATE_USER_URL
    login_tentativa = user_data.get('accountEmail', 'N/A') # Usa accountEmail para log

    try:
        logging.info(f"Tentando criar o usuário com email: {login_tentativa} via API: {url}")
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=45) # Timeout maior para criação?
        response.raise_for_status()
        logging.info(f"Resposta da API de criação de usuário recebida para {login_tentativa}.")
        # logging.debug(f"Resposta bruta criar usuário ({login_tentativa}): {response.text}")
        return response.json()
    except requests.exceptions.Timeout:
        logging.error(f"Erro durante a criação do usuário ({login_tentativa}) em {url}: Timeout.")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro durante a requisição de criação de usuário ({login_tentativa}) em {url}: {e}")
        if e.response is not None:
            logging.error(f"Detalhes da resposta de erro: Status={e.response.status_code}, Body={e.response.text}")
        return None
    except json.JSONDecodeError as e:
        resp_text = response.text if 'response' in locals() else 'N/A'
        logging.error(f"Erro ao decodificar JSON de criação de usuário ({login_tentativa}) em {url}: {e}. Resposta: {resp_text}")
        return None
    except Exception as e:
        logging.exception(f"Erro inesperado durante a criação do usuário: {login_tentativa}")
        return None


def add_user_to_group(auth_token, user_identifier, group_name):
    """
    Adiciona um usuário (pelo identificador fornecido) a um grupo via API.

    Args:
        auth_token (str): Token de autenticação.
        user_identifier (str): O identificador do usuário (login original do CSV)
                               a ser passado no campo 'uids'.
        group_name (str): Nome do grupo.

    Returns:
        dict or None: Resposta JSON da API ou None em caso de erro.
    """
    payload = {
        "id": ADD_GROUP_API_ID,
        "params": {
            "auth": auth_token,
            "uids": user_identifier, # API espera 'uids' - usando o identificador passado
            "cns": group_name
        }
    }
    headers = {"Content-Type": "application/json"}
    url = API_ADD_GROUP_URL

    try:
        logging.info(f"Tentando adicionar o ID/Login '{user_identifier}' ao grupo '{group_name}' via API: {url}")
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
        response.raise_for_status()
        logging.info(f"Resposta da API de adicionar ao grupo recebida para ID/Login '{user_identifier}' e grupo '{group_name}'.")
        # logging.debug(f"Resposta bruta adicionar grupo ({user_identifier} -> {group_name}): {response.text}")
        return response.json()
    except requests.exceptions.Timeout:
        logging.error(f"Erro ao adicionar ID/Login '{user_identifier}' ao grupo '{group_name}' em {url}: Timeout.")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro durante a requisição de adicionar ID/Login '{user_identifier}' ao grupo '{group_name}' em {url}: {e}")
        if e.response is not None:
             logging.error(f"Detalhes da resposta de erro: Status={e.response.status_code}, Body={e.response.text}")
        return None
    except json.JSONDecodeError as e:
        resp_text = response.text if 'response' in locals() else 'N/A'
        logging.error(f"Erro ao decodificar JSON de adicionar ao grupo para ID/Login '{user_identifier}' em {url}: {e}. Resposta: {resp_text}")
        return None
    except Exception as e:
        logging.exception(f"Erro inesperado ao adicionar ID/Login '{user_identifier}' ao grupo '{group_name}'.")
        return None

# --- Função de Geração de Senha (Atualizada) ---
def generate_random_password(length=PASSWORD_LENGTH):
    """
    Gera uma senha aleatória segura com letras, dígitos (pelo menos 2) e pontuação.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    # Remover caracteres ambíguos se desejado...
    # characters = ''.join(c for c in characters if c not in 'O0Il,;`\'"|\\{}')

    logging.debug(f"Gerando senha com {length} caracteres...")
    attempts = 0
    max_attempts = 100 # Prevenção contra loop infinito

    while attempts < max_attempts:
        attempts += 1
        password = ''.join(secrets.choice(characters) for _ in range(length))

        # Contar explicitamente os dígitos na senha gerada
        digit_count = sum(1 for c in password if c.isdigit())

        # Validar critérios, incluindo a exigência de >= 2 dígitos
        if (any(c.islower() for c in password)           # Pelo menos uma minúscula
                and any(c.isupper() for c in password)      # Pelo menos uma maiúscula
                and digit_count >= 2                      # <<< Pelo menos DOIS dígitos
                and any(c in string.punctuation for c in password) # Pelo menos um símbolo
           ):
            logging.info(f"Senha gerada com sucesso em {attempts} tentativa(s) ({length} caracteres, {digit_count} dígitos).")
            return password
        # else: # Log detalhado da falha (opcional)
        #     criteria_met = {
        #         "lower": any(c.islower() for c in password), "upper": any(c.isupper() for c in password),
        #         "digits": digit_count, "punctuation": any(c in string.punctuation for c in password) }
        #     logging.debug(f"Tentativa {attempts}: Senha '{password}' falhou. Detalhes: {criteria_met}")

    # Se sair do loop (muitas tentativas)
    logging.error(f"Falha ao gerar senha atendendo aos critérios após {max_attempts} tentativas.")
    raise ValueError(f"Não foi possível gerar uma senha válida (>=2 dígitos, etc.) após {max_attempts} tentativas.")


# --- Função Principal de Processamento ---
def create_users_from_csv(csv_filepath):
    """
    Lê um CSV, cria usuários via API usando um email formatado,
    adiciona a grupos pelo LOGIN ORIGINAL DO CSV e salva credenciais (email/senha).
    """
    user_credentials = []
    processed_count = 0
    success_count = 0
    error_count = 0

    # 1. Realizar Login uma única vez
    auth_token = perform_login()
    if not auth_token:
        logging.error("Falha no login inicial da API. O script não pode continuar.")
        messagebox.showerror("Erro de Login", "Falha ao obter token de autenticação da API.\nVerifique as credenciais (no código!), a conexão e o log.")
        return # Aborta a execução

    logging.info(f"Token de autenticação obtido. Iniciando processamento do CSV: {csv_filepath}")

    try:
        # Detectar encoding
        file_encoding = None
        encodings_to_try = ['utf-8-sig', 'utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        for enc in encodings_to_try:
            try:
                with open(csv_filepath, 'r', newline='', encoding=enc) as test_enc_file:
                    # Tenta ler a primeira linha ou cabeçalhos para validar
                    csv.DictReader(test_enc_file).fieldnames
                file_encoding = enc
                logging.info(f"Detectado encoding '{enc}' para o CSV.")
                break # Sai do loop se encontrar um encoding válido
            except (UnicodeDecodeError, TypeError, LookupError):
                continue # Tenta o próximo encoding
        if not file_encoding:
             logging.error(f"Não foi possível determinar um encoding válido para ler o arquivo CSV: {csv_filepath}")
             messagebox.showerror("Erro de Encoding", f"Não foi possível ler o arquivo CSV com os encodings testados ({', '.join(encodings_to_try)}). Verifique o formato do arquivo.")
             return


        with open(csv_filepath, 'r', newline='', encoding=file_encoding) as csvfile:
            reader = csv.DictReader(csvfile)
            # Validar cabeçalhos
            if not reader.fieldnames:
                 logging.error(f"Arquivo CSV '{csv_filepath}' (encoding: {file_encoding}) parece estar vazio ou não pôde ser lido corretamente.")
                 messagebox.showerror("Erro no CSV", f"Arquivo CSV '{os.path.basename(csv_filepath)}' está vazio ou inválido.")
                 return
            if 'login' not in reader.fieldnames or 'name' not in reader.fieldnames:
                logging.error(f"CSV '{csv_filepath}' não contém as colunas obrigatórias 'login' e 'name'. Cabeçalhos encontrados: {reader.fieldnames}")
                messagebox.showerror("Erro no CSV", f"Arquivo CSV '{os.path.basename(csv_filepath)}' deve conter as colunas 'login' e 'name'.")
                return

            logging.info(f"Cabeçalhos do CSV lidos com sucesso: {reader.fieldnames} (Encoding: {file_encoding})")

            # 2. Iterar sobre as linhas do CSV
            for i, row in enumerate(reader):
                processed_count += 1
                line_num = i + 2 # +1 para header, +1 para índice 0-based
                # Armazena o login original lido do CSV
                accountLogin = row.get('login', '').strip() # Valor original do CSV
                name = row.get('name', '').strip()

                logging.debug(f"Processando linha {line_num}: login='{accountLogin}', name='{name}'")

                if not accountLogin or not name:
                    logging.warning(f"Linha {line_num}: Dados incompletos (login='{accountLogin}', name='{name}'). Pulando.")
                    error_count += 1
                    continue

                # Criar a variável accountEmail para a criação do usuário
                if "@" in accountLogin:
                    accountEmail = accountLogin 
                    logging.debug(f"Linha {line_num}: Login '{accountLogin}' já contém '@'. Usando como email: {accountEmail}")
                else:
                    accountEmail = f"{accountLogin}{DEFAULT_DOMAIN_SUFFIX}"
                    logging.debug(f"Linha {line_num}: Sufixo '{DEFAULT_DOMAIN_SUFFIX}' adicionado ao login '{accountLogin}'. Resultando em email: {accountEmail}")

                # A variável 'accountLogin' (valor original do CSV) será usada para adicionar aos grupos.
                user_id_for_groups = accountLogin

                try:
                    password = generate_random_password()
                except ValueError as pass_err: # Captura erro se a geração falhar muitas vezes
                    logging.error(f"Linha {line_num}: Erro ao gerar senha para login '{accountLogin}'. Erro: {pass_err}. Pulando usuário.")
                    error_count += 1
                    continue # Pula para o próximo usuário

                # Monta o payload para CRIAR o usuário usando o accountEmail com a CHAVE CORRETA
                user_info = {
                    "auth": auth_token,
                    "accountEmail": accountEmail,  # Chave corrigida para a API de criação
                    "accountLogin": accountLogin,
                    "accountName": name,
                    "accountProfile": DEFAULT_PROFILE,
                    "accountPassword": password
                }

                # 3. Criar Usuário
                logging.info(f"Linha {line_num}: Tentando criar usuário com email '{accountEmail}'...")
                api_response_create = create_user(user_info)

                if api_response_create:
                    # Verificar se a resposta indica sucesso real (adapte conforme a API)
                    # Checa ausência da chave 'error' no dicionário principal da resposta
                    creation_successful = isinstance(api_response_create, dict) and 'error' not in api_response_create

                    if creation_successful:
                        logging.info(f"Linha {line_num}: Usuário com email '{accountEmail}' criado com sucesso.")

                        # 4. Adicionar aos Grupos usando o user_id_for_groups (login original)
                        group_errors = 0
                        logging.info(f"Linha {line_num}: Tentando adicionar login original '{user_id_for_groups}' aos grupos: {DEFAULT_GROUPS}")
                        for group in DEFAULT_GROUPS:
                            # Chama add_user_to_group usando o valor lido da coluna 'login' do CSV
                            api_response_group = add_user_to_group(auth_token, user_id_for_groups, group)
                            if api_response_group:
                                add_successful = isinstance(api_response_group, dict) and 'error' not in api_response_group
                                if add_successful:
                                     logging.info(f"Linha {line_num}: Login original '{user_id_for_groups}' adicionado com sucesso ao grupo '{group}'.")
                                else:
                                     logging.warning(f"Linha {line_num}: API indicou possível falha ao adicionar login original '{user_id_for_groups}' ao grupo '{group}'. Resposta: {api_response_group}")
                                     group_errors += 1
                            else:
                                logging.error(f"Linha {line_num}: Falha na requisição para adicionar login original '{user_id_for_groups}' ao grupo '{group}'.")
                                group_errors += 1

                        # 5. Armazenar credenciais (email completo e senha)
                        if group_errors == 0:
                            # Salva o EMAIL COMPLETO e a senha no CSV final
                            user_credentials.append({"login": accountEmail, "password": password})
                            success_count += 1
                        else:
                            logging.warning(f"Linha {line_num}: Usuário com email '{accountEmail}' criado, mas houve {group_errors} erro(s) ao adicioná-lo (Login original: '{user_id_for_groups}') aos grupos.")
                            # Salva o EMAIL COMPLETO mesmo com erro parcial
                            user_credentials.append({"login": accountEmail, "password": f"{password} [ERRO NOS GRUPOS]"})
                            error_count += 1 # Conta como erro parcial

                    else:
                        # Loga o erro específico retornado pela API se disponível
                        error_detail = api_response_create.get('error', {}).get('message', str(api_response_create))
                        logging.error(f"Linha {line_num}: API indicou falha ao criar usuário com email '{accountEmail}'. Detalhe: {error_detail}")
                        error_count += 1
                else:
                    logging.error(f"Linha {line_num}: Falha na requisição para criar usuário com email '{accountEmail}'. Nenhuma resposta JSON válida recebida.")
                    error_count += 1

        logging.info(f"Processamento do CSV concluído. Total de linhas lidas: {processed_count}, Sucessos: {success_count}, Falhas/Parciais: {error_count}")

        # 6. Gerar arquivo CSV com as credenciais
        if user_credentials:
            output_dir = os.path.dirname(csv_filepath)
            output_filepath = os.path.join(output_dir, OUTPUT_FILENAME)
            try:
                with open(output_filepath, 'w', newline='', encoding='utf-8') as output_csvfile:
                    # O cabeçalho do CSV final continua sendo "login", mas conterá o accountEmail
                    fieldnames = ["login", "password"]
                    writer = csv.DictWriter(output_csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(user_credentials)
                logging.info(f"Arquivo CSV com credenciais (email completo e senha) gerado em: {output_filepath}")
                # Mensagem final de sucesso
                messagebox.showinfo("Concluído",
                                    f"Processo finalizado.\n\n"
                                    f"Total de linhas lidas: {processed_count}\n"
                                    f"Usuários criados com sucesso (e adicionados aos grupos): {success_count}\n"
                                    f"Falhas ou erros parciais: {error_count}\n\n"
                                    f"Arquivo com credenciais salvo em:\n{output_filepath}")

                # ALERTA DE SEGURANÇA PÓS-CRIAÇÃO
                messagebox.showwarning("Atenção à Segurança!",
                                       f"O arquivo '{OUTPUT_FILENAME}' contém senhas!\n\n"
                                       "- Entregue-o de forma segura aos usuários.\n"
                                       "- NÃO o envie por email ou meios inseguros.\n"
                                       "- Exclua o arquivo de locais inseguros após o uso.")

            except IOError as e:
                logging.exception(f"Erro ao escrever o arquivo CSV de credenciais em {output_filepath}: {e}")
                messagebox.showerror("Erro de Gravação", f"Não foi possível salvar o arquivo de credenciais '{OUTPUT_FILENAME}':\n{e}")
            except Exception as e:
                 logging.exception(f"Erro inesperado ao gerar o arquivo CSV de credenciais: {e}")
                 messagebox.showerror("Erro Inesperado", f"Ocorreu um erro ao gerar o arquivo CSV de credenciais:\n{e}")

        # Mensagens de falha / arquivo vazio
        elif error_count == processed_count and processed_count > 0:
             messagebox.showerror("Falha Total", f"Nenhum usuário pôde ser criado com sucesso a partir do arquivo.\nTotal de linhas lidas: {processed_count}\nVerifique o arquivo '{LOG_FILENAME}' para detalhes.")
        elif processed_count == 0:
             messagebox.showwarning("Arquivo Vazio", "O arquivo CSV selecionado está vazio ou não contém dados válidos nas colunas 'login' e 'name'.")
        else: # Caso sem credenciais criadas, mas processou linhas (ex: todas inválidas)
             messagebox.showwarning("Concluído sem Sucesso", f"Processo finalizado, mas nenhum usuário foi criado com sucesso.\nTotal de linhas lidas: {processed_count}\nVerifique o arquivo '{LOG_FILENAME}'.")


    except FileNotFoundError:
        logging.error(f"Erro: Arquivo CSV não encontrado em {csv_filepath}")
        messagebox.showerror("Erro", f"Arquivo CSV não encontrado:\n{csv_filepath}")
    except PermissionError:
        logging.error(f"Erro de permissão ao ler o arquivo CSV: {csv_filepath}")
        messagebox.showerror("Erro de Permissão", f"Não foi possível ler o arquivo CSV.\nVerifique as permissões:\n{csv_filepath}")
    except Exception as e:
        logging.exception(f"Erro inesperado durante o processamento do CSV: {e}") # Log com stack trace
        messagebox.showerror("Erro Crítico", f"Ocorreu um erro inesperado durante o processamento:\n{e}\n\nVerifique o arquivo '{LOG_FILENAME}'.")


# --- Funções e Classes da Interface Gráfica (GUI) ---

def browse_file(entry_widget):
    """Abre diálogo para selecionar arquivo CSV e atualiza o campo de entrada."""
    filename = filedialog.askopenfilename(
        title="Selecione o arquivo CSV",
        filetypes=[("Arquivos CSV", "*.csv"), ("Todos os arquivos", "*.*")]
    )
    if filename:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)
        logging.info(f"Arquivo CSV selecionado pelo usuário: {filename}")

class QueueHandler(logging.Handler):
    """Envia registros de log para uma fila para serem processados pela GUI."""
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        # Formata a mensagem aqui para passar strings pela fila
        msg = self.format(record)
        try:
            self.log_queue.put_nowait(msg) # Evita bloquear se a fila estiver cheia
        except queue.Full:
             print(f"ALERTA: Fila de log da GUI cheia. Mensagem perdida: {msg}") # Fallback


class TkinterLogDisplay:
    """Exibe mensagens de log de uma fila em um widget Text do Tkinter."""
    POLL_INTERVAL = 150 # Intervalo de atualização da GUI em ms

    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.log_queue = queue.Queue()
        self.queue_handler = QueueHandler(self.log_queue)
        self.is_polling = False

        # Formatter para a GUI
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
        self.queue_handler.setFormatter(formatter)

        # Adiciona o handler da GUI ao logger raiz
        logging.getLogger().addHandler(self.queue_handler)
        self.start_polling()

    def display(self, record_str):
        """Escreve a string do registro no widget Text."""
        current_state = self.text_widget['state']
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, record_str + '\n')
        self.text_widget.configure(state=current_state)
        if self.text_widget.yview()[1] > 0.99: # Auto-scroll se no final
             self.text_widget.yview(tk.END)

    def poll_log_queue(self):
        """Verifica a fila por novas mensagens e as exibe."""
        while True:
            try:
                record_str = self.log_queue.get(block=False)
            except queue.Empty:
                break
            else:
                self.display(record_str)
        if self.is_polling:
            self.text_widget.after(self.POLL_INTERVAL, self.poll_log_queue)

    def start_polling(self):
        """Inicia a verificação periódica da fila de logs."""
        if not self.is_polling:
            self.is_polling = True
            self.text_widget.after(self.POLL_INTERVAL, self.poll_log_queue)

    def stop_polling(self):
        """Para a verificação periódica da fila de logs."""
        self.is_polling = False


def run_script_thread_wrapper(csv_filepath, run_button, browse_button, root):
    """Função executada na thread separada para não bloquear a GUI."""
    root.after(0, lambda: run_button.config(state=tk.DISABLED))
    root.after(0, lambda: browse_button.config(state=tk.DISABLED))
    logging.info(f"Iniciando processo em background para o arquivo: {csv_filepath}")

    try:
        create_users_from_csv(csv_filepath)
    except Exception as e:
        logging.exception("Erro crítico não capturado na thread de execução principal.")
        root.after(0, lambda: messagebox.showerror("Erro Crítico na Thread", f"Um erro muito inesperado ocorreu na thread:\n{e}\n\nVerifique o log."))
    finally:
        root.after(0, lambda: run_button.config(state=tk.NORMAL))
        root.after(0, lambda: browse_button.config(state=tk.NORMAL))
        logging.info("Thread de processamento finalizada.")


def start_run_script(csv_entry, run_button, browse_button, root):
    """Inicia a execução do script principal em uma nova thread."""
    csv_filepath = csv_entry.get().strip()
    if not csv_filepath:
        messagebox.showerror("Entrada Inválida", "Por favor, selecione o arquivo CSV primeiro.")
        logging.warning("Tentativa de execução sem selecionar arquivo CSV.")
        return

    if not os.path.isfile(csv_filepath):
         messagebox.showerror("Arquivo Não Encontrado", f"Arquivo CSV não encontrado no caminho especificado:\n{csv_filepath}")
         logging.error(f"Arquivo CSV selecionado não existe ou não é um arquivo: {csv_filepath}")
         return

    # Cria e inicia a thread
    thread = threading.Thread(
        target=run_script_thread_wrapper,
        args=(csv_filepath, run_button, browse_button, root),
        name="CSVProcessorThread",
        daemon=True
    )
    thread.start()


# --- Montagem da Interface Gráfica ---
def setup_gui():
    root = tk.Tk()
    root.title("Criador de Usuários API Expresso v2.3")
    root.minsize(650, 450)

    main_frame = tk.Frame(root, padx=10, pady=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # --- Linha 1: Seleção de Arquivo ---
    file_frame = tk.Frame(main_frame)
    file_frame.pack(fill=tk.X, pady=(0, 5))

    csv_filepath_label = tk.Label(file_frame, text="Arquivo CSV:")
    csv_filepath_label.pack(side=tk.LEFT, padx=(0, 5))

    csv_filepath_entry = tk.Entry(file_frame)
    csv_filepath_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    browse_button = tk.Button(file_frame, text="Procurar...", command=lambda: browse_file(csv_filepath_entry))
    browse_button.pack(side=tk.LEFT, padx=(5, 0))

    # --- Linha 2: Botão Executar ---
    run_button = tk.Button(main_frame, text="Executar Criação de Usuários", font=('Segoe UI', 10, 'bold'), height=2, relief=tk.RAISED, borderwidth=2)
    run_button.pack(fill=tk.X, pady=10)
    run_button.config(command=lambda: start_run_script(csv_filepath_entry, run_button, browse_button, root))

    # --- Linha 3: Área de Log ---
    log_label = tk.Label(main_frame, text="Log da Execução:")
    log_label.pack(anchor='w', pady=(5, 2))

    log_text_widget = scrolledtext.ScrolledText(main_frame, state='disabled', height=15, wrap=tk.WORD, font=('Consolas', 9))
    log_text_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

    # Configura o display de log da GUI
    log_display_instance = TkinterLogDisplay(log_text_widget)

    # Garante que o polling pare quando a janela for fechada
    def on_closing():
        logging.info("Janela fechada pelo usuário.")
        log_display_instance.stop_polling()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # --- Iniciar GUI ---
    logging.info("Interface gráfica configurada e pronta.")
    root.mainloop()
    logging.info("Aplicação finalizada.")
    logging.info("="*50 + "\n")


# --- Ponto de Entrada Principal ---
if __name__ == "__main__":
    # Handler opcional para exceções não capturadas
    def handle_exception(exc_type, exc_value, exc_traceback):
        logging.error("Erro não capturado globalmente:", exc_info=(exc_type, exc_value, exc_traceback))
        try: # Tenta mostrar erro na GUI
             messagebox.showerror("Erro Fatal Inesperado", f"Ocorreu um erro não tratado:\n{exc_value}\nO programa pode precisar ser fechado.\nVerifique o log.")
        except Exception:
             pass # Evita erro recursivo

    sys.excepthook = handle_exception # Ativa o handler global

    setup_gui() # Inicia a aplicação