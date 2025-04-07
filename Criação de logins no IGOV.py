import psycopg2
from psycopg2 import Error
import datetime
import csv
import os
import tkinter as tk
from tkinter import filedialog, messagebox

def connect_to_database(host, port, database, user, password):
    """
    Estabelece uma conexão com um banco de dados PostgreSQL.

    Args:
        host (str): O endereço do host do banco de dados.
        port (int): A porta do banco de dados.
        database (str): O nome do banco de dados.
        user (str): O nome de usuário para autenticação.
        password (str): A senha para autenticação.

    Returns:
        psycopg2.extensions.connection: Um objeto de conexão se a conexão for bem-sucedida, None caso contrário.
    """
    conn = None
    try:
        print(f"Tentando conectar ao banco de dados em {host}:{port}...")
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
        print("Conexão com o banco de dados estabelecida com sucesso.")
        return conn
    except Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        return None

def close_database_connection(conn):
    """
    Fecha a conexão com o banco de dados.

    Args:
        conn (psycopg2.extensions.connection): O objeto de conexão.
    """
    if conn:
        try:
            conn.close()
            print("Conexão com o banco de dados fechada.")
        except Error as e:
            print(f"Erro ao fechar a conexão com o banco de dados: {e}")

def execute_query(conn, query, data=None):
    """
    Executa uma consulta SQL no banco de dados.

    Args:
        conn (psycopg2.extensions.connection): O objeto de conexão.
        query (str): A consulta SQL a ser executada.
        data (tuple, optional): Dados para serem inseridos na consulta (para evitar SQL injection). Defaults to None.

    Returns:
        bool: True se a consulta foi executada com sucesso, False caso contrário.
    """
    if conn:
        try:
            cursor = conn.cursor()
            if data:
                cursor.execute(query, data)
            else:
                cursor.execute(query)
            conn.commit()  # Commit para salvar as alterações
            print("Query executada com sucesso.")
            return True
        except Error as e:
            print(f"Erro ao executar a consulta: {e}")
            conn.rollback() #desfaz a transação em caso de erro
            return False
        finally:
            if 'cursor' in locals():
                cursor.close()
    else:
        print("Não há conexão com o banco de dados.")
        return False

def get_orgao_id(conn, orgao_nome):
    """
    Obtém o ID do órgão com base no nome do órgão.

    Args:
        conn: Objeto de conexão com o banco de dados.
        orgao_nome (str): O nome do órgão.

    Returns:
        int or None: O ID do órgão se encontrado, None caso contrário.
    """
    query = "SELECT id FROM tb_orgao WHERE nome = %s;"
    try:
        cursor = conn.cursor()
        cursor.execute(query, (orgao_nome,))
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            print(f"Órgão '{orgao_nome}' não encontrado na tabela tb_orgao.")
            messagebox.showwarning("Aviso", f"Órgão '{orgao_nome}' não encontrado na tabela tb_orgao.")
            return None
    except Error as e:
        print(f"Erro ao buscar o ID do órgão: {e}")
        messagebox.showerror("Erro", f"Erro ao buscar o ID do órgão: {e}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()

def insert_key(conn, nome, orgao_nome, chave_politica):
    """
    Insere uma nova chave na tabela tb_chave com valores padrão, buscando o ID do órgão.

    Args:
        conn: Objeto de conexão com o banco de dados.
        nome (str): Nome da chave.
        orgao_nome (str): Nome do órgão da chave.
        chave_politica (str): Indica se é uma chave política ('S' ou 'N').

    Returns:
        bool: True se a inserção foi bem-sucedida, False caso contrário.
    """
    orgao_id = get_orgao_id(conn, orgao_nome)
    if orgao_id is None:
        return False

    query = """
        INSERT INTO tb_chave(nome, situacao, orgao, dt_criacao, dt_desativada, excluido, 
        chave_politica, cod_orgao)
        VALUES (%s, 'Ativa', %s, Now(), null, 'N', %s, %s);
    """
    data = (nome, orgao_nome, chave_politica, orgao_id)
    return execute_query(conn, query, data)

def insert_keys_from_csv(conn, csv_filepath):
    """
    Lê dados de um arquivo CSV e insere chaves na tabela tb_chave.

    Args:
        conn: Objeto de conexão com o banco de dados.
        csv_filepath (str): O caminho para o arquivo CSV.
    """
    try:
        with open(csv_filepath, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                nome = row.get('nome')
                orgao_nome = row.get('orgao')  # Agora pega o nome do órgão
                chave_politica = row.get('chave_politica')

                if not all([nome, orgao_nome, chave_politica]):
                    print(f"Erro: Dados incompletos na linha: {row}. Pulando para a próxima linha.")
                    messagebox.showwarning("Aviso", f"Dados incompletos na linha: {row}. Pulando para a próxima linha.")
                    continue

                if insert_key(conn, nome, orgao_nome, chave_politica):
                    print(f"Chave '{nome}' inserida com sucesso.")
                    messagebox.showinfo("Sucesso", f"Chave '{nome}' inserida com sucesso.")
                else:
                    print(f"Falha ao inserir a chave '{nome}'.")
                    messagebox.showerror("Erro", f"Falha ao inserir a chave '{nome}'.")

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
    
    # Dados de conexão
    host = "*"
    port = '*'
    database = "*"
    user = "*"
    password = "*"

    # Estabelece a conexão
    connection = connect_to_database(host, port, database, user, password)

    if connection:
        insert_keys_from_csv(connection, csv_filepath)
        close_database_connection(connection)
    else:
        print("Não foi possível estabelecer a conexão com o banco de dados.")
        messagebox.showerror("Erro", "Não foi possível estabelecer a conexão com o banco de dados.")

# Configuração da janela principal
root = tk.Tk()
root.title("Inserir Chaves no IGOV a partir de CSV")

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
