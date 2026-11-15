"""
vault.py
--------
Gerencia o ciclo de vida do cofre de credenciais:
- Estruturação de dados e serialização JSON.
- Gerador de senhas aleatórias de alta entropia com CSPRNG (secrets).
- Controle de desbloqueio em memória e sanitização ao fechar o cofre.
"""

import json
import secrets
import string
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    from src import crypto_engine
except ImportError:
    import crypto_engine


class Vault:
    def __init__(self, filepath: str = "vault.enc"):
        self.filepath = filepath
        self._master_key: Optional[bytearray] = None
        self._salt: Optional[bytes] = None
        self._entries: Dict[str, dict] = {}
        self.is_unlocked: bool = False

    def is_initialized(self) -> bool:
        """Verifica se o arquivo do cofre já existe no disco."""
        import os
        return os.path.exists(self.filepath)

    def initialize(self, master_password: str) -> None:
        """Inicializa um novo cofre do zero com um salt imprevisível."""
        if self.is_initialized():
            raise FileExistsError("O cofre já existe. Desbloqueie-o ou remova o arquivo existente.")

        import os
        self._salt = os.urandom(crypto_engine.SALT_LEN)
        self._master_key = crypto_engine.derive_key(master_password, self._salt)
        self._entries = {}
        self.is_unlocked = True
        self.save()

    def unlock(self, master_password: str) -> bool:
        """Carrega e decifra o cofre a partir do disco."""
        with open(self.filepath, "rb") as f:
            raw_bytes = f.read()

        salt, nonce, ciphertext = crypto_engine.unpack_vault_file(raw_bytes)
        derived_key = crypto_engine.derive_key(master_password, salt)

        try:
            plaintext = crypto_engine.decrypt_payload(nonce, ciphertext, derived_key)
            self._salt = salt
            self._master_key = derived_key
            self._entries = json.loads(plaintext.decode("utf-8"))
            self.is_unlocked = True
            return True
        except crypto_engine.InvalidTag:
            # Limpa imediatamente a chave derivada em caso de falha de autenticação
            crypto_engine.secure_zero_memory(derived_key)
            return False

    def save(self) -> None:
        """Cifra os registros em memória e salva no disco com um NOVO nonce único."""
        if not self.is_unlocked or self._master_key is None or self._salt is None:
            raise PermissionError("O cofre precisa estar desbloqueado para ser salvo.")

        raw_json = json.dumps(self._entries, ensure_ascii=False, indent=2).encode("utf-8")
        nonce, ciphertext = crypto_engine.encrypt_payload(raw_json, self._master_key)
        packed = crypto_engine.pack_vault_file(self._salt, nonce, ciphertext)

        with open(self.filepath, "wb") as f:
            f.write(packed)

    def lock(self) -> None:
        """Bloqueia a sessão e executa sanitização forçada da chave mestra e dos dados."""
        if self._master_key is not None:
            crypto_engine.secure_zero_memory(self._master_key)
            self._master_key = None

        self._entries.clear()
        self._salt = None
        self.is_unlocked = False

    def add_entry(self, service: str, username: str, password: str, notes: str = "") -> None:
        """Adiciona ou atualiza uma credencial no cofre."""
        if not self.is_unlocked:
            raise PermissionError("Cofre trancado.")

        self._entries[service.lower()] = {
            "service_name": service,
            "username": username,
            "password": password,
            "notes": notes,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        self.save()

    def get_entry(self, service: str) -> Optional[dict]:
        """Recupera os detalhes de um serviço."""
        if not self.is_unlocked:
            raise PermissionError("Cofre trancado.")
        return self._entries.get(service.lower())

    def list_services(self) -> List[str]:
        """Lista os nomes de serviços armazenados."""
        if not self.is_unlocked:
            raise PermissionError("Cofre trancado.")
        return sorted([v["service_name"] for v in self._entries.values()])

    def delete_entry(self, service: str) -> bool:
        """Remove um serviço do cofre."""
        if not self.is_unlocked:
            raise PermissionError("Cofre trancado.")
        key = service.lower()
        if key in self._entries:
            del self._entries[key]
            self.save()
            return True
        return False

    @staticmethod
    def generate_secure_password(length: int = 20, use_symbols: bool = True) -> str:
        """
        Gera uma senha com entropia uniforme usando secrets.choice (CSPRNG).
        Garante pelo menos 1 maiúscula, 1 minúscula, 1 dígito e 1 caractere especial.
        """
        if length < 8:
            raise ValueError("O comprimento mínimo recomendado para a senha é de 8 caracteres.")

        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?" if use_symbols else ""

        alphabet = lower + upper + digits + symbols

        # Amostragem com garantia de cada classe
        mandatory = [
            secrets.choice(lower),
            secrets.choice(upper),
            secrets.choice(digits)
        ]
        if use_symbols:
            mandatory.append(secrets.choice(symbols))

        remaining = [secrets.choice(alphabet) for _ in range(length - len(mandatory))]
        password_chars = mandatory + remaining

        # Embaralhamento criptograficamente seguro via Fisher-Yates com secrets.randbelow
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        return "".join(password_chars)