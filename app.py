import sqlite3      # Biblioteca para trabalhar com banco SQLite
import hashlib      # Biblioteca para gerar hash (vamos usar PBKDF2)
import os           # Usada para gerar bytes aleatórios (salt)
import getpass      # Lê senha sem mostrar no terminal (mais seguro)

DB_NAME = "senhas.db"  # Nome do arquivo do banco SQLite (vai aparecer na pasta do projeto)


# --------------------------
# BANCO: criar tabela
# --------------------------
def criar_banco():
    # Abre conexão com o arquivo do banco (se não existir, ele cria)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor() 

    # Cria a tabela "usuarios" se ela ainda não existir
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)

    conn.commit()  # Salva as mudanças no banco
    conn.close()   # Fecha a conexão com o banco


# --------------------------
# HASH: senha segura (hash + salt)
# --------------------------
def gerar_hash_senha(senha: str, salt: bytes) -> str:
    # PBKDF2 é um método forte para hash de senha usando hashlib
    # - sha256: algoritmo base
    # - senha.encode: transforma a string em bytes
    # - salt: bytes aleatórios
    # - 100_000: quantidade de iterações (deixa mais difícil quebrar)
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        100_000
    )

    # Transformamos o hash em texto hex para armazenar no banco
    return hash_bytes.hex()


# --------------------------
# CADASTRO (com confirmação)
# --------------------------
def cadastrar_usuario():
    username = input("Username: ").strip()  # strip remove espaços antes/depois

    # Regras simples para username
    if len(username) < 3:
        print("Username deve ter pelo menos 3 caracteres.")
        return

    # getpass esconde a senha no terminal
    senha = getpass.getpass("Senha: ").strip()
    confirmar = getpass.getpass("Confirmar senha: ").strip()

    # Regra simples para senha
    if len(senha) < 8:
        print("Senha deve ter pelo menos 8 caracteres.")
        return

    # Confirmação (evita cadastrar errado)
    if senha != confirmar:
        print("As senhas não conferem. Tente novamente.")
        return

    # salt aleatório (16 bytes) -> ajuda a proteger contra rainbow table e repetição de hashes
    salt = os.urandom(16)

    # Gera o hash da senha usando salt
    senha_hash = gerar_hash_senha(senha, salt)

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Usamos ? para evitar SQL Injection
        # salt.hex() -> converte bytes para string para salvar no SQLite
        cursor.execute(
            "INSERT INTO usuarios (username, senha_hash, salt) VALUES (?, ?, ?)",
            (username, senha_hash, salt.hex())
        )

        conn.commit()
        conn.close()
        print("Usuário cadastrado com sucesso!")

    except sqlite3.IntegrityError:
        # Esse erro acontece quando o username é repetido (porque é UNIQUE)
        print("Esse username já existe. Tente outro.")


# --------------------------
# LOGIN
# --------------------------
def login():
    username = input("Username: ").strip()
    senha = getpass.getpass("Senha: ").strip()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Busca os dados do usuário pelo username
    cursor.execute("SELECT id, username, senha_hash, salt FROM usuarios WHERE username = ?", (username,))
    usuario = cursor.fetchone()  # fetchone pega um único registro (ou None)
    conn.close()

    if not usuario:
        print("Usuário não encontrado.")
        return None

    # Desempacota a tupla retornada do banco
    user_id, user_name, senha_hash_salva, salt_hex = usuario

    # Converte salt salvo (texto hex) de volta para bytes
    salt = bytes.fromhex(salt_hex)

    # Gera o hash da senha digitada com o mesmo salt do usuário
    senha_hash_digitada = gerar_hash_senha(senha, salt)

    # Se o hash bater, senha está correta
    if senha_hash_digitada == senha_hash_salva:
        print("Login feito com sucesso!")
        return {"id": user_id, "username": user_name}

    print("Senha incorreta.")
    return None


# --------------------------
# TROCAR SENHA (somente logado)
# --------------------------
def trocar_senha(usuario_logado):
    print("\n=== Trocar minha senha ===")
    senha_atual = getpass.getpass("Senha atual: ").strip()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Pega hash e salt do usuário logado pelo ID (mais confiável que username)
    cursor.execute("SELECT senha_hash, salt FROM usuarios WHERE id = ?", (usuario_logado["id"],))
    row = cursor.fetchone()

    if not row:
        conn.close()
        print("Usuário não encontrado no banco (algo deu errado).")
        return

    senha_hash_salva, salt_hex = row
    salt_atual = bytes.fromhex(salt_hex)

    # Confere se a senha atual está correta
    senha_hash_digitada = gerar_hash_senha(senha_atual, salt_atual)
    if senha_hash_digitada != senha_hash_salva:
        conn.close()
        print("Senha atual incorreta.")
        return

    # Pede nova senha e confirmação
    nova = getpass.getpass("Nova senha: ").strip()
    confirmar = getpass.getpass("Confirmar nova senha: ").strip()

    if len(nova) < 8:
        conn.close()
        print("Nova senha deve ter pelo menos 8 caracteres.")
        return

    if nova != confirmar:
        conn.close()
        print("As senhas não conferem.")
        return

    # Boa prática: gerar um NOVO salt para a nova senha
    # Isso evita reaproveitar o mesmo salt e melhora a segurança
    novo_salt = os.urandom(16)
    novo_hash = gerar_hash_senha(nova, novo_salt)

    # Atualiza senha_hash e salt no banco
    cursor.execute(
        "UPDATE usuarios SET senha_hash = ?, salt = ? WHERE id = ?",
        (novo_hash, novo_salt.hex(), usuario_logado["id"])
    )

    conn.commit()
    conn.close()

    print("Senha atualizada com sucesso!")


# --------------------------
# LISTAR USUÁRIOS + COUNT
# --------------------------
def listar_usuarios():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # COUNT(*) retorna quantos registros existem na tabela
    cursor.execute("SELECT COUNT(*) FROM usuarios")
    total = cursor.fetchone()[0]  # pega o primeiro (e único) valor retornado

    # Pega todos usuários (mas só id e username; nunca listamos hashes)
    cursor.execute("SELECT id, username FROM usuarios ORDER BY id ASC")
    usuarios = cursor.fetchall()

    conn.close()

    print("\n=== Usuários cadastrados ===")
    print(f"Total de usuários: {total}\n")

    for u in usuarios:
        print(f"ID: {u[0]} | Username: {u[1]}")

    print("===========================\n")


# --------------------------
# MENU PRINCIPAL
# --------------------------
def menu():
    usuario_logado = None  # guarda o usuário logado (id e username)

    while True:
        print("\n=== Sistema de Controle de Senhas ===")
        print("1) Cadastrar usuário")
        print("2) Login")
        print("3) Listar usuários (precisa estar logado)")
        print("4) Trocar minha senha (precisa estar logado)")
        print("5) Logout")
        print("6) Sair")

        opcao = input("Escolha: ").strip()

        if opcao == "1":
            cadastrar_usuario()

        elif opcao == "2":
            usuario_logado = login()

        elif opcao == "3":
            # Listagem controlada: só deixa listar se estiver logado
            if usuario_logado:
                listar_usuarios()
            else:
                print("Você precisa estar logado para listar usuários.")

        elif opcao == "4":
            # Trocar senha: só se estiver logado
            if usuario_logado:
                trocar_senha(usuario_logado)
            else:
                print("Você precisa estar logado para trocar a senha.")

        elif opcao == "5":
            # Logout simples: apaga o usuário logado da variável
            if usuario_logado:
                usuario_logado = None
                print("Logout realizado.")
            else:
                print("Você não está logado.")

        elif opcao == "6":
            print("Saindo...")
            break

        else:
            print("Opção inválida.")


# --------------------------
# START
# --------------------------
if __name__ == "__main__":
    # Garante que a tabela exista antes de começar
    criar_banco()

    # Abre o menu do sistema
    menu()
