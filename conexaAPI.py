import requests
import json
import csv
import tkinter as tk
from tkinter import filedialog, messagebox

def perform_login():
    """
    Realiza uma requisição de login para a API com credenciais fixas e retorna a resposta.

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
            "user": "expressoadmin-celepar-qliksense",  # Nome de usuário fixo
            "password": "Adad2066!@seuze2"  # Senha fixa
        }
    }

    try:
        print("\nTentando realizar o login...")  # Log
        response = requests.post(url, headers=headers, data=json.dumps(payload))  # Envia a requisição POST
        response.raise_for_status()  # Lança uma exceção HTTPError para respostas ruins (4xx ou 5xx)
        print("Resposta da API de Login (bruta):")  # Log
        print(response.text)  # Log - Imprime a resposta completa
        return response.json()  # Retorna a resposta JSON
    except requests.exceptions.RequestException as e:
        print(f"Erro durante a requisição de login: {e}")  # Imprime erro de requisição
        return None
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON de login: {e}")  # Imprime erro de decodificação JSON
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
        print(f"\nTentando criar o usuário: {user_data['accountLogin']}...")  # Log
        response = requests.post(url, headers=headers, data=json.dumps(payload))  # Envia a requisição POST
        response.raise_for_status()  # Lança uma exceção HTTPError para respostas ruins (4xx ou 5xx)
        print(f"Resposta da API de criação de usuário (bruta) para {user_data['accountLogin']}:")  # Log
        print(response.text)  # Log - Imprime a resposta completa
        return response.json()  # Retorna a resposta JSON
    except requests.exceptions.RequestException as e:
        print(f"Erro durante a requisição de criação de usuário: {e}")  # Imprime erro de requisição
        return None
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON de criação de usuário: {e}")  # Imprime erro de decodificação JSON
        return None

def add_user_to_group(auth_token, user_ids, group_names):
    """
    Adiciona um usuário a um grupo através de uma requisição POST para o endpoint /celepar/Admin/AddUserToGroup.

    Args:
        auth_token (str): O token de autenticação.
        user_ids (str): O ID ou IDs de usuário(s) a serem adicionados ao grupo (pode ser string única ou multiplas separadas por virgula).
        group_names (str): O nome ou nomes do grupo(s) ao(s) qual(is) o(s) usuário(s) será(ão) adicionado(s) (pode ser string única ou multiplas separadas por virgula).

    Returns:
        dict or None: A resposta JSON da API se bem-sucedido, None caso contrário.
    """
    url = "https://api-slim.expresso.pr.gov.br/celepar/Admin/AddUserToGroup"  # URL do endpoint
    headers = {
        "Content-Type": "application/json"  # Define o tipo de conteúdo como JSON
    }
    payload = {
        "id": 93,  # ID fixo para a requisição
        "params": {
            "auth": auth_token,
            "uids": user_ids,
            "cns": group_names
        }
    }

    try:
        print(f"\nTentando adicionar o usuário {user_ids} ao grupo {group_names}...")  # Log
        response = requests.post(url, headers=headers, data=json.dumps(payload))  # Envia a requisição POST
        response.raise_for_status()  # Lança uma exceção HTTPError para respostas ruins (4xx ou 5xx)
        print(f"Resposta da API de adicionar ao grupo (bruta) para {user_ids}:")  # Log
        print(response.text)  # Log - Imprime a resposta completa
        return response.json()  # Retorna a resposta JSON
    except requests.exceptions.RequestException as e:
        print(f"Erro durante a requisição de adicionar ao grupo: {e}")  # Imprime erro de requisição
        return None
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON de adicionar ao grupo: {e}")  # Imprime erro de decodificação JSON
        return None

def create_users_from_csv(csv_filepath):
    """
    Lê dados de um arquivo CSV e cria usuários na API.

    Args:
        csv_filepath (str): O caminho para o arquivo CSV.
    """
    try:
        with open(csv_filepath, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Realiza o login uma única vez
            login_response = perform_login()
            auth = None

            if login_response:
                print("\nResposta da API de Login (JSON):")
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
                
                if not auth:
                    print("Erro: O token 'auth' está vazio ou não foi encontrado. Não é possível criar o usuário.")
                    messagebox.showerror("Erro", "O token 'auth' está vazio ou não foi encontrado. Não é possível criar o usuário.")
                    return

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
                    
                    # Adiciona o usuário aos grupos após a criação bem-sucedida
                    groups_to_add = ["grupo-qliksense-active_directory", "grupo-qliksense-default"]
                    for group in groups_to_add:
                        # Corrected line: Pass the 'auth' token to the function
                        api_response_add_to_group = add_user_to_group(auth, login, group)
                        if api_response_add_to_group:
                            print(f"Usuário {login} adicionado ao grupo {group}.")
                            print("Resposta da API (Adicionar ao Grupo):")
                            print(json.dumps(api_response_add_to_group, indent=2, ensure_ascii=False))
                            messagebox.showinfo("Sucesso", f"Usuário {login} adicionado ao grupo {group}.")
                        else:
                            print(f"Falha ao adicionar usuário {login} ao grupo {group}.")
                            messagebox.showerror("Erro", f"Falha ao adicionar usuário {login} ao grupo {group}.")
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

    if not csv_filepath:
        messagebox.showerror("Erro", "Por favor, selecione o arquivo CSV.")
        return

    create_users_from_csv(csv_filepath)

# Configuração da janela principal
root = tk.Tk()
root.title("Criar Usuários e Adicionar a Grupos a partir de CSV")

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