# -*- coding: utf-8 -*-

# === Script para Inserção de Chaves IGOV via CSV ===
# Lê chaves de um CSV, insere em lote no PostgreSQL, com GUI e logging.
# ATENÇÃO: Contém credenciais de BD fixas no código (NÃO SEGURO!).
# Versão: 3.0 (Logging, Threading, Batch Insert, Encoding Detection)

import psycopg2
from psycopg2 import Error
import csv
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import logging
import threading
import queue
import sys
import os

# --- Constantes de Configuração ---
BATCH_SIZE = 100 # Número de registros por lote de inserção no BD
OUTPUT_FILENAME = "db_insert_summary.txt" # Arquivo opcional para salvar resumo
LOG_FILENAME = "db_insert_log.log" # Nome do arquivo de log

# --- Configuração do Logging ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s') # Configuração base

# File Handler
file_handler = logging.FileHandler(LOG_FILENAME, encoding='utf-8', mode='a') # 'a' para append
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)

# Console Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO) # Pode ser DEBUG se precisar de mais detalhes no console

# Adiciona handlers ao logger raiz
logger = logging.getLogger()
logger.addHandler(file_handler)
logger.addHandler(console_handler)
logger.setLevel(logging.INFO) # Define o nível mínimo para o logger raiz

logger.info("="*50)
logger.info("Aplicação de Inserção de Chaves iniciada.")
logger.info(f"Log será salvo em: {LOG_FILENAME}")
logger.info(f"Tamanho do lote de inserção: {BATCH_SIZE}")
logger.info("="*50)


# --- Funções de Banco de Dados ---

def connect_to_database(host, port, database, user, password):
    """
    Estabelece uma conexão com um banco de dados PostgreSQL.
    Retorna o objeto de conexão ou None em caso de erro.
    """
    conn = None
    conn_string = f"host='{host}' port='{port}' dbname='{database}' user='{user}'"
    logger.info(f"Tentando conectar ao banco de dados: {conn_string} password=***")
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            connect_timeout=10 # Timeout para estabelecer conexão
        )
        conn.autocommit = False # Garantir controle de transação manual
        logger.info(f"Conexão com o banco de dados '{database}' estabelecida com sucesso.")
        return conn
    except Error as e:
        logger.error(f"Erro ao conectar ao banco de dados: {e}", exc_info=False) # Não logar stack trace completo por padrão
        logger.debug("Detalhes do erro de conexão:", exc_info=True) # Logar stack trace em modo DEBUG
        return None
    except Exception as e:
        logger.exception(f"Erro inesperado durante a conexão com o banco de dados.") # Logar outras exceções
        return None


def close_database_connection(conn):
    """Fecha a conexão com o banco de dados de forma segura."""
    if conn and not conn.closed:
        try:
            conn.close()
            logger.info("Conexão com o banco de dados fechada.")
        except Error as e:
            logger.error(f"Erro ao fechar a conexão com o banco de dados: {e}")
        except Exception as e:
             logger.exception("Erro inesperado ao fechar conexão.")


def _insert_batch(conn, data_batch):
    """
    (Helper) Insere um lote de dados na tabela indicadores.tb_chave.
    Retorna True em sucesso, False em erro. Não faz commit/rollback aqui.
    """
    if not data_batch:
        return True # Nada a fazer

    query = """
        INSERT INTO indicadores.tb_chave(nome, situacao, orgao, dt_criacao, dt_desativada,
        excluido, chave_politica, cod_orgao)
        VALUES (%s, 'Ativa', %s, Now(), null, 'N', %s, null);
    """
    cursor = None
    try:
        cursor = conn.cursor()
        # psycopg2 adapta a lista de tuplas para executemany
        cursor.executemany(query, data_batch)
        logger.debug(f"Executemany com {len(data_batch)} registros concluído.")
        return True
    except Error as e:
        logger.error(f"Erro ao executar inserção em lote (executemany): {e}")
        # Logar talvez o primeiro item do lote para depuração
        if data_batch:
             logger.debug(f"Primeiro item do lote com erro: {data_batch[0]}")
        return False
    except Exception as e:
        logger.exception("Erro inesperado durante _insert_batch.")
        return False
    finally:
        if cursor:
            try:
                cursor.close()
            except Exception as e_cur:
                 logger.error(f"Erro ao fechar cursor em _insert_batch: {e_cur}")


# --- Função Principal de Processamento ---

def process_csv_and_insert(conn, csv_filepath):
    """
    Lê o CSV, valida dados e chama a inserção em lote.
    Gerencia commits e rollbacks por lote.
    Retorna tupla: (success_count, error_count, processed_count)
    """
    batch_data = []
    processed_count = 0
    success_count = 0
    error_count = 0
    file_encoding = None

    # 1. Detectar Encoding
    encodings_to_try = ['utf-8-sig', 'utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
    logger.info(f"Tentando detectar encoding do arquivo CSV: {csv_filepath}")
    for enc in encodings_to_try:
        try:
            with open(csv_filepath, 'r', newline='', encoding=enc) as test_enc_file:
                # Lê uma pequena parte para testar o encoding
                test_enc_file.read(1024)
                # Se chegou aqui sem erro, assume que o encoding está OK
            file_encoding = enc
            logger.info(f"Detectado encoding '{enc}' para o CSV.")
            break
        except (UnicodeDecodeError, TypeError, LookupError, FileNotFoundError):
             logger.debug(f"Encoding '{enc}' falhou, tentando próximo...")
             continue
    if not file_encoding:
         logger.error(f"Não foi possível determinar um encoding válido para ler o arquivo CSV: {csv_filepath}")
         raise ValueError(f"Encoding não suportado ou arquivo inválido: {os.path.basename(csv_filepath)}") # Levanta erro

    # 2. Ler CSV e Processar em Lotes
    logger.info(f"Iniciando leitura do CSV '{os.path.basename(csv_filepath)}' com encoding '{file_encoding}'.")
    try:
        with open(csv_filepath, 'r', newline='', encoding=file_encoding) as csvfile:
            reader = csv.DictReader(csvfile)
            # Validar cabeçalhos
            if not reader.fieldnames:
                 logger.error("Arquivo CSV parece estar vazio ou não possui cabeçalho.")
                 raise ValueError("Arquivo CSV vazio ou sem cabeçalho.")
            required_columns = {'nome', 'orgao', 'chave_politica'}
            if not required_columns.issubset(set(map(str.lower, reader.fieldnames))): # Checa case-insensitive
                 logger.error(f"CSV não contém as colunas obrigatórias: {required_columns}. Encontradas: {reader.fieldnames}")
                 raise ValueError(f"Colunas obrigatórias ({required_columns}) não encontradas no CSV.")

            logger.info(f"Cabeçalhos do CSV validados: {reader.fieldnames}")

            # Iterar sobre as linhas
            for i, row in enumerate(reader):
                processed_count += 1
                line_num = i + 2 # Linha real no arquivo

                # Normalizar nomes das chaves do dicionário (para case-insensitive)
                row_lower = {k.lower(): v for k, v in row.items()}

                nome = row_lower.get('nome', '').strip()
                orgao_nome = row_lower.get('orgao', '').strip()
                chave_politica = row_lower.get('chave_politica', '').strip().upper() # Converte para maiúsculo para facilitar validação

                # Validar dados da linha
                if not nome or not orgao_nome or not chave_politica:
                    logger.warning(f"Linha {line_num}: Dados incompletos (nome='{nome}', orgao='{orgao_nome}', politica='{chave_politica}'). Pulando.")
                    error_count += 1
                    continue
                if chave_politica not in ('S', 'N'):
                    logger.warning(f"Linha {line_num}: Valor inválido para 'chave_politica' ('{chave_politica}'). Deve ser 'S' ou 'N'. Pulando.")
                    error_count += 1
                    continue

                # Adicionar dados formatados ao lote
                batch_data.append((nome, orgao_nome, chave_politica))
                logger.debug(f"Linha {line_num}: Dados adicionados ao lote: {(nome, orgao_nome, chave_politica)}")

                # Inserir o lote se atingir o tamanho definido
                if len(batch_data) >= BATCH_SIZE:
                    logger.info(f"Atingido tamanho do lote ({len(batch_data)}). Inserindo no banco de dados...")
                    if _insert_batch(conn, batch_data):
                        conn.commit() # Commit do lote bem-sucedido
                        logger.info(f"Lote de {len(batch_data)} registros inserido e commit realizado com sucesso.")
                        success_count += len(batch_data)
                    else:
                        conn.rollback() # Rollback do lote com erro
                        logger.error(f"Erro ao inserir lote de {len(batch_data)} registros. Rollback realizado.")
                        error_count += len(batch_data) # Assume que todo o lote falhou
                    batch_data.clear() # Limpa o lote após tentativa de inserção

            # Inserir qualquer lote restante no final do arquivo
            if batch_data:
                logger.info(f"Inserindo lote final com {len(batch_data)} registro(s)...")
                if _insert_batch(conn, batch_data):
                    conn.commit()
                    logger.info(f"Lote final de {len(batch_data)} registros inserido e commit realizado com sucesso.")
                    success_count += len(batch_data)
                else:
                    conn.rollback()
                    logger.error(f"Erro ao inserir lote final de {len(batch_data)} registros. Rollback realizado.")
                    error_count += len(batch_data)
                batch_data.clear()

    except FileNotFoundError:
        logger.error(f"Erro Crítico: Arquivo CSV não encontrado em {csv_filepath}")
        raise # Re-levanta a exceção para ser tratada no nível superior
    except ValueError as ve: # Captura erros de validação levantados aqui
        logger.error(f"Erro de validação: {ve}")
        raise # Re-levanta
    except Exception as e:
        logger.exception(f"Erro inesperado durante o processamento do CSV e inserção.")
        # Tentar rollback em caso de erro inesperado durante a leitura/processamento
        try:
            conn.rollback()
            logger.info("Rollback realizado devido a erro inesperado no processamento.")
        except Error as rb_err:
            logger.error(f"Erro ao tentar realizar rollback após erro inesperado: {rb_err}")
        raise # Re-levanta a exceção original

    logger.info(f"Processamento concluído. Total: {processed_count}, Sucessos: {success_count}, Falhas: {error_count}")
    return success_count, error_count, processed_count


# --- Funções e Classes da Interface Gráfica (GUI) ---

def browse_file(entry_widget):
    """Abre diálogo para selecionar arquivo CSV e atualiza o campo de entrada."""
    # Mostra info ANTES de abrir o diálogo
    messagebox.showinfo(
        "Formato do Arquivo CSV",
        "O arquivo CSV deve conter as seguintes colunas (sem sensibilidade a maiúsculas/minúsculas):\n\n"
        "  • nome: Nome da chave (texto)\n"
        "  • orgao: Nome do órgão (texto)\n"
        "  • chave_politica: 'S' ou 'N' (texto)"
    )
    filename = filedialog.askopenfilename(
        title="Selecione o arquivo CSV",
        filetypes=[("Arquivos CSV", "*.csv"), ("Todos os arquivos", "*.*")]
    )
    if filename:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)
        logger.info(f"Arquivo CSV selecionado pelo usuário: {filename}")

class QueueHandler(logging.Handler):
    """Envia registros de log para uma fila para serem processados pela GUI."""
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        msg = self.format(record)
        try:
            self.log_queue.put_nowait(msg)
        except queue.Full:
             print(f"ALERTA: Fila de log da GUI cheia. Mensagem perdida: {msg}")

class TkinterLogDisplay:
    """Exibe mensagens de log de uma fila em um widget Text do Tkinter."""
    POLL_INTERVAL = 150 # ms

    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.log_queue = queue.Queue()
        self.queue_handler = QueueHandler(self.log_queue)
        self.is_polling = False
        # Configura o handler da GUI para ter um nível potencialmente diferente (ex: DEBUG)
        self.queue_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
        self.queue_handler.setFormatter(formatter)
        logging.getLogger().addHandler(self.queue_handler)
        self.start_polling()

    def display(self, record_str):
        current_state = self.text_widget['state']
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, record_str + '\n')
        self.text_widget.configure(state=current_state)
        if self.text_widget.yview()[1] > 0.99:
             self.text_widget.yview(tk.END)

    def poll_log_queue(self):
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
        if not self.is_polling:
            self.is_polling = True
            self.text_widget.after(self.POLL_INTERVAL, self.poll_log_queue)

    def stop_polling(self):
        self.is_polling = False


def run_script_thread_wrapper(csv_filepath, run_button, browse_button, root):
    """Função executada na thread separada para não bloquear a GUI."""
    root.after(0, lambda: run_button.config(state=tk.DISABLED))
    root.after(0, lambda: browse_button.config(state=tk.DISABLED))
    logger.info(f"Iniciando processo em background para o arquivo: {csv_filepath}")

    conn = None
    success = 0
    errors = 0
    total = 0
    final_message = "Processo finalizado."
    message_type = "info" # 'info', 'warning', 'error'

    try:
        # ####################################################################
        # !! ALERTA DE SEGURANÇA !! As credenciais estão fixas aqui !!
        # Modifique para carregar de forma segura (env var, config file, etc.)
        # ####################################################################
        host = "*"
        port = *
        database = "*"
        user = "*"
        password = "*" # MUITO INSEGURO

        conn = connect_to_database(host, port, database, user, password)

        if conn:
            # Chama a função principal de processamento
            success, errors, total = process_csv_and_insert(conn, csv_filepath)
            # Monta mensagem final
            final_message = (
                f"Processo Concluído.\n\n"
                f"Arquivo: {os.path.basename(csv_filepath)}\n"
                f"Total de Linhas Processadas: {total}\n"
                f"Registros Inseridos com Sucesso: {success}\n"
                f"Linhas com Erro/Puladas: {errors}\n\n"
                f"Consulte o arquivo '{LOG_FILENAME}' para detalhes."
            )
            if errors > 0:
                message_type = "warning"
            logger.info("Processamento principal concluído na thread.")

        else:
            logger.error("Falha ao estabelecer conexão com o banco de dados. Processo abortado.")
            final_message = "Erro Crítico: Não foi possível conectar ao banco de dados.\nVerifique as configurações e o log."
            message_type = "error"

    except ValueError as ve: # Captura erros de validação do CSV/Encoding
         logger.error(f"Erro de validação durante o processamento: {ve}")
         final_message = f"Erro de Validação:\n{ve}\n\nProcesso abortado."
         message_type = "error"
    except Exception as e:
        logger.exception("Erro crítico não capturado na thread de execução principal.")
        final_message = f"Erro Crítico Inesperado na Thread:\n{e}\n\nVerifique o log '{LOG_FILENAME}'.\nProcesso abortado."
        message_type = "error"
    finally:
        # Garante que a conexão seja fechada, não importa o que aconteça
        if conn:
            close_database_connection(conn)

        # Reabilitar botões e mostrar mensagem final (via GUI thread)
        root.after(0, lambda: run_button.config(state=tk.NORMAL))
        root.after(0, lambda: browse_button.config(state=tk.NORMAL))
        logger.info("Thread de processamento finalizada.")

        # Escolhe o tipo de messagebox baseado no resultado
        if message_type == "info":
            root.after(0, lambda: messagebox.showinfo("Concluído", final_message))
        elif message_type == "warning":
             root.after(0, lambda: messagebox.showwarning("Concluído com Avisos", final_message))
        else: # error
             root.after(0, lambda: messagebox.showerror("Erro Crítico", final_message))


def start_run_script(csv_entry, run_button, browse_button, root):
    """Verifica o caminho do CSV e inicia a execução em uma nova thread."""
    csv_filepath = csv_entry.get().strip()
    if not csv_filepath:
        messagebox.showerror("Entrada Inválida", "Por favor, selecione o arquivo CSV primeiro.")
        logger.warning("Tentativa de execução sem selecionar arquivo CSV.")
        return

    if not os.path.isfile(csv_filepath):
         messagebox.showerror("Arquivo Não Encontrado", f"Arquivo CSV não encontrado no caminho especificado:\n{csv_filepath}")
         logger.error(f"Arquivo CSV selecionado não existe ou não é um arquivo: {csv_filepath}")
         return

    # Cria e inicia a thread
    thread = threading.Thread(
        target=run_script_thread_wrapper,
        args=(csv_filepath, run_button, browse_button, root),
        name="CSVInsertThread", # Nomeia a thread
        daemon=True
    )
    thread.start()


# --- Montagem da Interface Gráfica ---
def setup_gui():
    root = tk.Tk()
    root.title("Inserir Chaves IGOV (CSV to DB) v3.0")
    root.minsize(700, 500) # Aumentado para acomodar melhor o log

    main_frame = tk.Frame(root, padx=10, pady=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # --- Linha 1: Seleção de Arquivo ---
    file_frame = tk.Frame(main_frame)
    file_frame.pack(fill=tk.X, pady=(0, 5))

    csv_filepath_label = tk.Label(file_frame, text="Arquivo CSV:")
    csv_filepath_label.pack(side=tk.LEFT, padx=(0, 5))

    csv_filepath_entry = tk.Entry(file_frame, width=60) # Aumenta um pouco o campo
    csv_filepath_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    browse_button = tk.Button(file_frame, text="Procurar...", command=lambda: browse_file(csv_filepath_entry))
    browse_button.pack(side=tk.LEFT, padx=(5, 0))

    # --- Linha 2: Botão Executar ---
    run_button = tk.Button(main_frame, text="Executar Inserção no Banco de Dados", font=('Segoe UI', 10, 'bold'), height=2, relief=tk.RAISED, borderwidth=2)
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
        logger.info("Janela fechada pelo usuário.")
        if log_display_instance:
            log_display_instance.stop_polling()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # --- Iniciar GUI ---
    logger.info("Interface gráfica configurada e pronta.")
    root.mainloop()
    logger.info("Aplicação finalizada.")
    logger.info("="*50 + "\n")


# --- Ponto de Entrada Principal ---
if __name__ == "__main__":
    # Handler opcional para exceções não capturadas
    def handle_exception(exc_type, exc_value, exc_traceback):
        # Loga primeiro
        logger.error("Erro não capturado globalmente:", exc_info=(exc_type, exc_value, exc_traceback))
        # Tenta mostrar erro na GUI se possível
        try:
             messagebox.showerror("Erro Fatal Inesperado", f"Ocorreu um erro não tratado:\n{exc_value}\nO programa pode precisar ser fechado.\nVerifique o log '{LOG_FILENAME}'.")
        except Exception as e:
            print(f"Falha ao mostrar messagebox de erro fatal: {e}") # Fallback para console

    sys.excepthook = handle_exception # Ativa o handler global

    setup_gui() # Inicia a aplicação