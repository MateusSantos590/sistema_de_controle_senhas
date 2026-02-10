import sqlite3           # Manipuação do banco de dados
import hashlib       # Fornece algoritmos de criptografia. Usamos para o PBKDF2, que transforma a senha em um código irreversível (hash).
import os         # Interage com o Sistema Operaconal 
from typing import Optional, List, Dict

class GerenciadorDB:
    """Classe back-end para gestão de utilizadores e segurança de senhas."""
    
    def __init__(self, nome_db: str = "sistema.db"):
        self.nome_db = nome_db
        self._instalar_esquema()

    def _get_conexao(self):
        return sqlite3.connect(self.nome_db)

    def _instalar_esquema(self):
        """Cria a tabela inicial se não existir."""
        query = """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        );
        """
        with self._get_conexao() as conn:
            conn.execute(query)

    def _gerar_hash(self, senha: str, salt: bytes) -> str:
        """Gera hash PBKDF2-HMAC-SHA256 de alta segurança."""
        return hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, 100_000).hex()

    def cadastrar_usuario(self, username: str, senha: str) -> bool:
        """Regista um novo utilizador. Retorna Falso se o username já existir."""
        salt = os.urandom(16)
        senha_hash = self._gerar_hash(senha, salt)
        try:
            with self._get_conexao() as conn:
                conn.execute(
                    "INSERT INTO usuarios (username, senha_hash, salt) VALUES (?, ?, ?)",
                    (username, senha_hash, salt.hex())
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def validar_login(self, username: str, senha: str) -> Optional[Dict]:
        """Verifica credenciais e retorna dados do utilizador ou None."""
        with self._get_conexao() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, senha_hash, salt FROM usuarios WHERE username = ?", (username,))
            user = cursor.fetchone()

        if user:
            u_id, u_name, u_hash, u_salt_hex = user
            if self._gerar_hash(senha, bytes.fromhex(u_salt_hex)) == u_hash:
                return {"id": u_id, "username": u_name}
        return None

    def alterar_senha(self, user_id: int, nova_senha: str):
        """Atualiza a senha com um novo salt aleatório."""
        novo_salt = os.urandom(16)
        novo_hash = self._gerar_hash(nova_senha, novo_salt)
        with self._get_conexao() as conn:
            conn.execute(
                "UPDATE usuarios SET senha_hash = ?, salt = ? WHERE id = ?",
                (novo_hash, novo_salt.hex(), user_id)
            )

    def obter_todos_usuarios(self) -> List[Dict]:
        """Lista todos os utilizadores (apenas ID e Username)."""
        with self._get_conexao() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username FROM usuarios")
            return [{"id": r[0], "username": r[1]} for r in cursor.fetchall()]
