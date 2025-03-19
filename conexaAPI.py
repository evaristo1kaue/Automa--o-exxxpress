import requests
import json
import csv
import tkinter as tk
from tkinter import filedialog, messagebox

def perform_login(username, password):
    """
    Realiza uma requisição de login para a API e retorna a resposta.

    Args:
        username (str): O nome de usuário para login.
        password (str): A senha para login.

    Returns:
        dict or None: A resposta JSON da API se bem-sucedido, None caso contrário.
    """
    url = "https://api-slim.expresso.pr.gov.br/celepar/Login"  # URL do endpoint de login
    headers = {
        "Content-Type": "application/json"  # Define o tipo de conteúdo como JSON
    }
    payload = {
        "id": 99,  # ID fixo para a requisição de login
        "params": {
            "user": username,  # Nome de usuário fornecido
            "password": password  # Senha fornecida
        }
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))  # Envia a requisição POST
        response.raise_for_status()  # Lança uma exceção HTTPError para respostas ruins (4xx ou 5xx)
        return response.json()  # Retorna a resposta JSON
    except requests.exceptions.RequestException as e:
        print(f"Erro durante a requisição: {e}")  # Imprime erro de requisição
        return None
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON: {e}")  # Imprime erro de decodificação JSON
        return None

def create_user(user_data):
    """
    Cria um novo usuário via uma requisição POST para o endpoint /celepar/Admin/CreateUser.

    Args:
        user_data (dict): Um dicionário contendo as informações do usuário
                          (auth, accountLogin, accountEmail, accountName, accountProfile, accountPassword).

    Returns:
        dict or None: A resposta JSON da API se bem-sucedido, None caso contrário.
    """
    url = "https://api-slim.expresso.pr.gov.br/celepar/Admin/CreateUser"  # URL do endpoint de criação de usuário
    headers = {
        "Content-Type": "application/json"  # Define o tipo de conteúdo como JSON
    }
    payload = {
        "id": 64,  # O ID é fixo conforme o comando cURL
        "params": user_data  # Dados do usuário fornecidos
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))  # Envia a requisição POST
        response.raise_for_status()  # Lança uma exceção HTTPError para respostas ruins (4xx ou 5xx)
        return response.json()  # Retorna a resposta JSON
    except requests.exceptions.RequestException as e:
        print(f"Erro durante a requisição: {e}")  # Imprime erro de requisição
        return None
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON: {e}")  # Imprime erro de decodificação JSON
        return None

def create_users_from_csv(csv_filepath, username_login, password_login):
    """
    Lê dados de um arquivo CSV e cria usuários na API.

    Args:
        csv_filepath (str): O caminho para o arquivo CSV.
        username_login (str): O nome de usuário para o login inicial.
        password_login (str): A senha para o login inicial.
    """
    try:
        with open(csv_filepath, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Realiza o login uma única vez
            login_response = perform_login(username_login, password_login)
            auth = None

            if login_response:
                print("Resposta da API de Login:")
                print(json.dumps(login_response, indent=2, ensure_ascii=False))

                # Lógica de diagnóstico para encontrar o 'auth'
                if "auth" in login_response:
                    auth = login_response["auth"]
                elif "result" in login_response and "auth" in login_response["result"]:
                    auth = login_response["result"]["auth"]
                elif "data" in login_response and "auth" in login_response["data"]:
                    auth = login_response["data"]["auth"]
                elif "token" in login_response:
                    auth = login_response["token"]
                
                if auth:
                    print(f"\nValor de Auth: {auth}")
                else:
                    print("\nA chave 'auth' não foi encontrada na resposta da API. Não é possível criar os usuários.")
                    messagebox.showerror("Erro", "A chave 'auth' não foi encontrada na resposta da API.")
                    return
            else:
                print("Login falhou. Não é possível criar os usuários.")
                messagebox.showerror("Erro", "Login falhou. Não é possível criar os usuários.")
                return

            # Itera sobre as linhas do CSV e cria os usuários
            for row in reader:
                login = row.get('login')
                email = row.get('e-mail')
                name = row.get('name')
                profile = row.get('profile')
                password = row.get('password')

                if not all([login, email, name, profile, password]):
                    print(f"Erro: Dados incompletos na linha: {row}. Pulando para a próxima linha.")
                    messagebox.showwarning("Aviso", f"Dados incompletos na linha: {row}. Pulando para a próxima linha.")
                    continue

                user_info = {
                    "auth": auth,
                    "accountLogin": login,
                    "accountEmail": email,
                    "accountName": name,
                    "accountProfile": profile,
                    "accountPassword": password
                }

                api_response_create_user = create_user(user_info)

                if api_response_create_user:
                    print(f"\nUsuário {login} criado com sucesso.")
                    print("Resposta da API (Criar Usuário):")
                    print(json.dumps(api_response_create_user, indent=2, ensure_ascii=False))
                    messagebox.showinfo("Sucesso", f"Usuário {login} criado com sucesso.")
                else:
                    print(f"\nFalha ao criar usuário {login}.")
                    messagebox.showerror("Erro", f"Falha ao criar usuário {login}.")

    except FileNotFoundError:
        print(f"Erro: Arquivo CSV não encontrado em {csv_filepath}")
        messagebox.showerror("Erro", f"Arquivo CSV não encontrado em {csv_filepath}")
    except Exception as e:
        print(f"Erro inesperado: {e}")
        messagebox.showerror("Erro", f"Erro inesperado: {e}")

def browse_file():
    """Abre uma janela para selecionar o arquivo CSV."""
    filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if filename:
        csv_filepath_entry.delete(0, tk.END)
        csv_filepath_entry.insert(0, filename)

def run_script():
    """Executa o script com os dados fornecidos na interface."""
    csv_filepath = csv_filepath_entry.get()
    username_login = username_entry.get()
    password_login = password_entry.get()

    if not csv_filepath or not username_login or not password_login:
        messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
        return

    create_users_from_csv(csv_filepath, username_login, password_login)

# Configuração da janela principal
root = tk.Tk()
root.title("Criar Usuários a partir de CSV")

# Rótulo e entrada para o caminho do arquivo CSV
csv_filepath_label = tk.Label(root, text="Caminho do Arquivo CSV:")
csv_filepath_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

csv_filepath_entry = tk.Entry(root, width=50)
csv_filepath_entry.grid(row=0, column=1, padx=5, pady=5)

browse_button = tk.Button(root, text="Procurar", command=browse_file)
browse_button.grid(row=0, column=2, padx=5, pady=5)

# Rótulo e entrada para o nome de usuário
username_label = tk.Label(root, text="Usuário de Login:")
username_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

username_entry = tk.Entry(root, width=50)
username_entry.grid(row=1, column=1, padx=5, pady=5)

# Rótulo e entrada para a senha
password_label = tk.Label(root, text="Senha de Login:")
password_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")

password_entry = tk.Entry(root, show="*", width=50)
password_entry.grid(row=2, column=1, padx=5, pady=5)

# Botão para executar o script
run_button = tk.Button(root, text="Executar", command=run_script)
run_button.grid(row=3, column=0, columnspan=3, padx=5, pady=10)

root.mainloop()