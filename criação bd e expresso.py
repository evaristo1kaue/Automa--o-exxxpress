import psycopg2
from psycopg2 import Error
import csv
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import json
import random
import string
import logging
import sys

# --- Logging ---

logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Credentials (Hardcoded) ---

DATABASE_HOST = "10.15.39.218"  # Replace with your database host
DATABASE_PORT = 5432  # Replace with your database port
DATABASE_NAME = "igov"  # Replace with your database name
DATABASE_USER = "sa_igov"  # Replace with your database user
DATABASE_PASSWORD = "stranger"  # Replace with your database password

# --- Expresso API Credentials (Hardcoded) ---

EXPRESSO_API_USER = "expressoadmin-celepar-qliksense"  # Replace with your Expresso API user
EXPRESSO_API_PASSWORD = "Adad2066!@seuze2"  # Replace with your Expresso API password
EXPRESSO_PASSWORD_LENGTH = 8  # default is 5

# --- Database Functions ---

def connect_to_database():
    """
    Estabelece uma conexão com um banco de dados PostgreSQL.
    """
    conn = None
    try:
        logging.info(f"Tentando conectar ao banco de dados em {DATABASE_HOST}:{DATABASE_PORT}...")
        conn = psycopg2.connect(
            host=DATABASE_HOST,
            port=DATABASE_PORT,
            database=DATABASE_NAME,
            user=DATABASE_USER,
            password=DATABASE_PASSWORD,
            connect_timeout=5  # Add a timeout
        )
        logging.info("Conexão com o banco de dados estabelecida com sucesso.")
        return conn
    except Error as e:
        logging.error(f"Erro ao conectar ao banco de dados: {e}")
        messagebox.showerror("Error", f"Erro ao conectar ao banco de dados: {e}")
        return None

def close_database_connection(conn):
    """
    Fecha a conexão com o banco de dados.
    """
    if conn:
        try:
            conn.close()
            logging.info("Conexão com o banco de dados fechada.")
        except Error as e:
            logging.error(f"Erro ao fechar a conexão com o banco de dados: {e}")

def execute_query(conn, query, data=None):
    """
    Executa uma consulta SQL no banco de dados.
    """
    if conn:
        try:
            cursor = conn.cursor()
            if data:
                cursor.execute(query, data)
            else:
                cursor.execute(query)
            conn.commit()
            logging.info(f"Query executada com sucesso: {query}")
            return True
        except Error as e:
            logging.error(f"Erro ao executar a consulta: {e}")
            logging.error(f"Query que falhou: {query}")
            conn.rollback()
            return False
        finally:
            if 'cursor' in locals():
                cursor.close()
    else:
        logging.error("Não há conexão com o banco de dados.")
        return False

def insert_key(conn, nome, orgao_nome, chave_politica):
    """
    Insere uma nova chave na tabela indicadores.tb_chave.
    """
    query = """
        INSERT INTO indicadores.tb_chave(nome, situacao, orgao, dt_criacao, dt_desativada, 
        excluido, chave_politica, cod_orgao)
        VALUES (%s, 'Ativa', %s, Now(), null, 'N', %s, null);
    """
    data = (nome, orgao_nome, chave_politica)
    return execute_query(conn, query, data)

# --- Expresso API Functions ---

def perform_login():
    """
    Realiza uma requisição de login para a API Expresso.
    """
    url = "https://api-slim.expresso.pr.gov.br/celepar/Login"
    headers = {"Content-Type": "application/json"}

    logging.info(f"Tentando realizar o login na API Expresso com o usuário: {EXPRESSO_API_USER}")

    payload = {
        "id": 99,
        "params": {
            "user": EXPRESSO_API_USER,
            "password": EXPRESSO_API_PASSWORD
        }
    }

    try:
        logging.info("\nTentando realizar o login na API Expresso...")
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        logging.debug(f"Resposta da API de Login (bruta): {response.text}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro durante a requisição de login: {e}")
        messagebox.showerror("Error", f"Erro durante a requisição de login: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Erro ao decodificar JSON de login: {e}")
        messagebox.showerror("Error", f"Erro ao decodificar JSON de login: {e}")
        return None

def create_user(user_data):
    """
    Cria um novo usuário via API Expresso.
    """
    url = "https://api-slim.expresso.pr.gov.br/celepar/Admin/CreateUser"
    headers = {"Content-Type": "application/json"}
    payload = {"id": 64, "params": user_data}

    try:
        logging.info(f"\nTentando criar o usuário: {user_data['accountLogin']}...")
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        logging.debug(f"Resposta da API de criação de usuário (bruta) para {user_data['accountLogin']}: {response.text}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro durante a requisição de criação de usuário: {e}")
        messagebox.showerror("Error", f"Erro durante a requisição de criação de usuário: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Erro ao decodificar JSON de criação de usuário: {e}")
        messagebox.showerror("Error", f"Erro ao decodificar JSON de criação de usuário: {e}")
        return None

def add_user_to_group(auth_token, user_ids, group_names):
    """
    Adiciona um usuário a um grupo via API Expresso.
    """
    url = "https://api-slim.expresso.pr.gov.br/celepar/Admin/AddUserToGroup"
    headers = {"Content-Type": "application/json"}
    payload = {
        "id": 93,
        "params": {
            "auth": auth_token,
            "uids": user_ids,
            "cns": group_names
        }
    }

    try:
        logging.info(f"\nTentando adicionar o usuário {user_ids} ao grupo {group_names}...")
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        logging.debug(f"Resposta da API de adicionar ao grupo (bruta) para {user_ids}: {response.text}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro durante a requisição de adicionar ao grupo: {e}")
        messagebox.showerror("Error", f"Erro durante a requisição de adicionar ao grupo: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Erro ao decodificar JSON de adicionar ao grupo: {e}")
        messagebox.showerror("Error", f"Erro ao decodificar JSON de adicionar ao grupo: {e}")
        return None

def generate_random_password(length=None):
    """Gera uma senha aleatória."""
    if length is None:
        length = EXPRESSO_PASSWORD_LENGTH
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def process_csv_row(conn, row, auth):
    """
    Processa uma linha do CSV, inserindo uma chave no banco de dados ou criando um usuário na API Expresso.
    """
    nome_completo = row.get('nome_completo')
    login = row.get('login')
    orgao = row.get('orgao')
    chave_politica = row.get('chave_politica')

    if not nome_completo:
        logging.warning(f"Nome completo não encontrado na linha: {row}. Pulando para a próxima linha.")
        messagebox.showwarning("Aviso", f"Nome completo não encontrado na linha: {row}. Pulando para a próxima linha.")
        return

    if login:  # If login is present, create a user
        profile = "qliksense"
        password = generate_random_password()

        if login and "@" not in login:
            login = f"{login}@nodomain.com"

        if not all([login, nome_completo, profile, password]):
            logging.warning(f"Dados incompletos para usuário na linha: {row}. Pulando para a próxima linha.")
            messagebox.showwarning("Aviso", f"Dados incompletos para usuário na linha: {row}. Pulando para a próxima linha.")
            return

        if not auth:
            logging.error("Erro: O token 'auth' está vazio ou não foi encontrado. Não é possível criar o usuário.")
            messagebox.showerror("Erro", "O token 'auth' está vazio ou não foi encontrado. Não é possível criar o usuário.")
            return

        user_info = {
            "auth": auth,
            "accountLogin": login,
            "accountName": nome_completo,
            "accountProfile": profile,
            "accountPassword": password
        }

        api_response_create_user = create_user(user_info)

        if api_response_create_user:
            logging.info(f"\nUsuário {login} criado com sucesso com a senha: {password}.")
            logging.debug("Resposta da API (Criar Usuário):")
            logging.debug(json.dumps(api_response_create_user, indent=2, ensure_ascii=False))
            messagebox.showinfo("Sucesso", f"Usuário {login} criado com sucesso com a senha: {password}.")

            groups_to_add = ["grupo-qliksense-active_directory", "grupo-qliksense-default"]
            for group in groups_to_add:
                api_response_add_to_group = add_user_to_group(auth, login, group)
                if api_response_add_to_group:
                    logging.info(f"Usuário {login} adicionado ao grupo {group}.")
                    logging.debug("Resposta da API (Adicionar ao Grupo):")
                    logging.debug(json.dumps(api_response_add_to_group, indent=2, ensure_ascii=False))
                    messagebox.showinfo("Sucesso", f"Usuário {login} adicionado ao grupo {group}.")
                else:
                    logging.error(f"Falha ao adicionar usuário {login} ao grupo {group}.")
                    messagebox.showerror("Erro", f"Falha ao adicionar usuário {login} ao grupo {group}.")
        else:
            logging.error(f"\nFalha ao criar usuário {login}.")
            messagebox.showerror("Erro", f"Falha ao criar usuário {login}.")

    else:  # If login is not present, insert a key
        if not all([nome_completo, orgao, chave_politica]):
            logging.warning(f"Dados incompletos para chave na linha: {row}. Pulando para a próxima linha.")
            messagebox.showwarning("Aviso", f"Dados incompletos para chave na linha: {row}. Pulando para a próxima linha.")
            return

        if chave_politica not in ('S', 'N'):
            logging.warning(f"Valor inválido para 'chave_politica' na linha: {row}. Deve ser 'S' ou 'N'. Pulando para a próxima linha.")
            messagebox.showwarning("Aviso", f"Valor inválido para 'chave_politica' na linha: {row}. Deve ser 'S' ou 'N'. Pulando para a próxima linha.")
            return

        if insert_key(conn, nome_completo, orgao, chave_politica):
            logging.info(f"Chave '{nome_completo}' inserida com sucesso.")
            messagebox.showinfo("Sucesso", f"Chave '{nome_completo}' inserida com sucesso.")
        else:
            logging.error(f"Falha ao inserir a chave '{nome_completo}'.")
            messagebox.showerror("Erro", f"Falha ao inserir a chave '{nome_completo}'.")

def process_csv(csv_filepath):
    """
    Lê dados de um arquivo CSV e processa as linhas para inserir chaves ou criar usuários.
    """
    connection = connect_to_database()

    if not connection:
        logging.error("Não foi possível estabelecer a conexão com o banco de dados.")
        messagebox.showerror("Erro", "Não foi possível estabelecer a conexão com o banco de dados.")
        return

    try:
        with open(csv_filepath, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            logging.info(f"Cabeçalhos do CSV: {reader.fieldnames}") #check the headers
            login_response = perform_login()
            auth = None

            if login_response:
                logging.info("\nResposta da API de Login (JSON):")
                logging.debug(json.dumps(login_response, indent=2, ensure_ascii=False))

                if "auth" in login_response:
                    auth = login_response["auth"]
                elif "result" in login_response and "auth" in login_response["result"]:
                    auth = login_response["result"]["auth"]
                elif "data" in login_response and "auth" in login_response["data"]:
                    auth = login_response["data"]["auth"]
                elif "token" in login_response:
                    auth = login_response["token"]

                if auth:
                    logging.info(f"\nValor de Auth: {auth}")
                else:
                    logging.error("\nA chave 'auth' não foi encontrada na resposta da API. Não é possível criar os usuários.")
                    messagebox.showerror("Erro", "A chave 'auth' não foi encontrada na resposta da API.")
                    return
            else:
                logging.error("Login falhou. Não é possível criar os usuários.")
                messagebox.showerror("Erro", "Login falhou. Não é possível criar os usuários.")
                return

            for row in reader:
                process_csv_row(connection, row, auth)
    except FileNotFoundError:
        logging.error(f"Erro: Arquivo CSV não encontrado em {csv_filepath}")
        messagebox.showerror("Erro", f"Arquivo CSV não encontrado em {csv_filepath}")
    except Exception as e:
        logging.exception(f"Erro inesperado: {e}")
        messagebox.showerror("Erro", f"Erro inesperado: {e}")
    finally:
        close_database_connection(connection)

# --- Combined Script Logic ---

def browse_file():
    """Abre uma janela para selecionar o arquivo CSV."""
    messagebox.showinfo(
        "Formato do Arquivo CSV",
        "O arquivo CSV deve conter as seguintes colunas:\n\n"
        "nome_completo: Nome completo do usuário (texto).\n"
        "login: Login do usuário (texto) (opcional, apenas para criação de usuário).\n"
        "orgao: Nome do órgão (texto) (opcional, apenas para inserção de chave).\n"
        "chave_politica: Indica se é uma chave política ('S' para Sim, 'N' para Não) (texto) (opcional, apenas para inserção de chave).\n"
    )
    filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if filename:
        csv_filepath_entry.delete(0, tk.END)
        csv_filepath_entry.insert(0, filename)

def run_script():
    """Executa o script com os dados fornecidos na interface."""
    csv_filepath = csv_filepath_entry.get()

    if not csv_filepath:
        messagebox.showerror("Erro", "Por favor, selecione o arquivo CSV.")
        return

    process_csv(csv_filepath)

# --- GUI Setup ---

root = tk.Tk()
root.title("IGOV e Expresso - Inserção de Dados")

# Rótulo e entrada para o caminho do arquivo CSV
csv_filepath_label = tk.Label(root, text="Caminho do Arquivo CSV:")
csv_filepath_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

csv_filepath_entry = tk.Entry(root, width=50)
csv_filepath_entry.grid(row=0, column=1, padx=5, pady=5)

browse_button = tk.Button(root, text="Procurar", command=browse_file)
browse_button.grid(row=0, column=2, padx=5, pady=5)

# Botão para executar o script
run_button = tk.Button(root, text="Executar", command=run_script)
run_button.grid(row=1, column=0, columnspan=3, padx=5, pady=10)

root.mainloop()