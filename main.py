import sqlite3 as con

# Criando tabelas
sql_cliente = "CREATE TABLE IF NOT EXISTS cliente(ID_CLIENTE INTEGER PRIMARY KEY" \
"LOGIN VARCHAR(40) NOT NULL," \
"EMAIL VARCHAR(40) NOT NULL," \
"NOME VARCHAR(40) NOT NULL," \
"SENHA VARCHAR(10) NOT NULL," \
"CONFIRMA SENHA VARCHAR(10) NOT NULL" \
"PERFIL (20) NOT NULL)"

try:
    conexao = con.connect('cadastro.db')
    cursor = conexao.cursor()
    cursor.execute(sql_cliente)
    conexao.commit()

except con.DatabaseError as erro:
    print("Erro ao criar tabela", erro)
finally:
    if conexao:
        conexao.close()