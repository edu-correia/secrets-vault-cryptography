"""
vault.py
--------
Gerencia o ciclo de vida do cofre de credenciais:
- Estruturação de dados e serialização JSON.
- Gerador de senhas aleatórias de alta entropia com CSPRNG (secrets).
- Controle da sessão e sobrescrita do buffer mutável da chave ao trancar.
"""

import json
import os
import secrets
import stat
import string
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    from src import crypto_engine
except ImportError:
    import crypto_engine


PASSWORD_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


class VaultFormatError(ValueError):
    """O arquivo ou os registros decifrados não seguem o formato esperado."""


class Vault:
    MIN_MASTER_PASSWORD_LENGTH = 15

    def __init__(self, filepath: str | os.PathLike[str] = "vault.enc"):
        self.filepath = filepath
        self._master_key: Optional[bytearray] = None
        self._salt: Optional[bytes] = None
        self._entries: Dict[str, dict] = {}
        self.is_unlocked: bool = False

    def is_initialized(self) -> bool:
        """Reconhece apenas arquivos regulares e rejeita links simbólicos."""
        try:
            mode = os.lstat(self.filepath).st_mode
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(mode):
            raise PermissionError("O cofre deve ser um arquivo regular, sem link simbólico.")
        return True

    @classmethod
    def validate_master_password(cls, password: str) -> None:
        if not password.strip() or len(password) < cls.MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                "Use uma frase-senha imprevisível com pelo menos "
                f"{cls.MIN_MASTER_PASSWORD_LENGTH} caracteres."
            )

    def initialize(self, master_password: str) -> None:
        """Inicializa um novo cofre do zero com um salt imprevisível."""
        if self.is_initialized():
            raise FileExistsError("O cofre já existe. Desbloqueie-o ou remova o arquivo existente.")

        self.validate_master_password(master_password)
        self.lock()
        self._salt = os.urandom(crypto_engine.SALT_LEN)
        try:
            self._master_key = crypto_engine.derive_key(master_password, self._salt)
            self._write_entries({}, create=True)
            self.is_unlocked = True
        finally:
            if not self.is_unlocked:
                self.lock()

    def unlock(self, master_password: str) -> bool:
        """Abre o cofre, retornando False apenas se a autenticação falhar."""
        self.lock()
        self.validate_master_password(master_password)
        if not self.is_initialized():
            raise FileNotFoundError("Arquivo do cofre não encontrado.")

        def open_regular_file(path, flags):
            return os.open(
                path, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            )

        with open(self.filepath, "rb", opener=open_regular_file) as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise PermissionError("O cofre deve ser um arquivo regular.")
            raw_bytes = f.read()

        try:
            salt, nonce, ciphertext = crypto_engine.unpack_vault_file(raw_bytes)
        except ValueError as exc:
            raise VaultFormatError(str(exc)) from None

        derived_key = crypto_engine.derive_key(master_password, salt)

        try:
            plaintext = crypto_engine.decrypt_payload(nonce, ciphertext, derived_key)
            entries = self._decode_entries(plaintext)
            self._salt = salt
            self._master_key = derived_key
            self._entries = entries
            self.is_unlocked = True
            return True
        except crypto_engine.InvalidTag:
            return False
        finally:
            if not self.is_unlocked:
                crypto_engine.secure_zero_memory(derived_key)
                self.lock()

    @staticmethod
    def _decode_entries(plaintext: bytes) -> Dict[str, dict]:
        try:
            entries = json.loads(plaintext.decode("utf-8"))
        except (ValueError, RecursionError):
            raise VaultFormatError("O conteúdo decifrado não é um JSON válido em UTF-8.") from None

        fields = ("service_name", "username", "password", "notes", "updated_at")
        if not isinstance(entries, dict) or any(
            not isinstance(entry, dict)
            or not all(isinstance(entry.get(field), str) for field in fields)
            or entry["service_name"].lower() != key
            for key, entry in entries.items()
        ):
            raise VaultFormatError("O conteúdo decifrado tem registros em formato inválido.")
        return entries

    def save(self) -> None:
        """Cifra os registros com um novo nonce aleatório e substitui o arquivo."""
        if not self.is_unlocked:
            raise PermissionError("O cofre precisa estar desbloqueado para ser salvo.")
        self._write_entries(self._entries)

    def _write_entries(self, entries: Dict[str, dict], *, create: bool = False) -> None:
        if self._master_key is None or self._salt is None:
            raise PermissionError("Chave do cofre indisponível.")
        raw_json = json.dumps(entries, ensure_ascii=False, indent=2).encode("utf-8")
        nonce, ciphertext = crypto_engine.encrypt_payload(raw_json, self._master_key)
        packed = crypto_engine.pack_vault_file(self._salt, nonce, ciphertext)

        path = Path(self.filepath)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
                temporary = Path(f.name)
                f.write(packed)
                f.flush()
                os.fsync(f.fileno())

            if create:
                # Publica o arquivo completo sem substituir outro cofre.
                os.link(temporary, path)
            else:
                if not self.is_initialized():
                    raise FileNotFoundError("O arquivo do cofre foi movido ou removido.")
                os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def lock(self) -> None:
        """Zera o buffer mutável da chave e descarta referências aos registros."""
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

        entries = self._entries.copy()
        entries[service.lower()] = {
            "service_name": service,
            "username": username,
            "password": password,
            "notes": notes,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        self._write_entries(entries)
        self._entries = entries

    def get_entry(self, service: str) -> Optional[dict]:
        """Recupera os detalhes de um serviço."""
        if not self.is_unlocked:
            raise PermissionError("Cofre trancado.")
        entry = self._entries.get(service.lower())
        return entry.copy() if entry is not None else None

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
            entries = self._entries.copy()
            del entries[key]
            self._write_entries(entries)
            self._entries = entries
            return True
        return False

    @staticmethod
    def check_password_strength(password: str) -> tuple[str, list[str]]:
        """Avalia comprimento e classes de caracteres para orientar o usuário."""
        score = 2 if len(password) >= 12 else int(len(password) >= 8)
        feedback = []
        if len(password) < 12:
            feedback.append("Prefira uma senha com pelo menos 12 caracteres.")

        checks = (
            (str.islower, "Inclua letras minúsculas."),
            (str.isupper, "Inclua letras maiúsculas."),
            (str.isdecimal, "Inclua números."),
            (PASSWORD_SYMBOLS.__contains__, "Inclua um símbolo se o serviço permitir."),
        )
        for matches, suggestion in checks:
            if any(matches(char) for char in password):
                score += 1
            else:
                feedback.append(suggestion)
        levels = ("Muito fraca", "Muito fraca", "Muito fraca", "Fraca", "Fraca", "Razoável", "Forte")
        return levels[score], feedback

    @staticmethod
    def generate_secure_password(length: int = 20, use_symbols: bool = True) -> str:
        """
        Gera uma senha usando secrets.choice (CSPRNG), com pelo menos uma
        maiúscula, uma minúscula, um dígito e, se habilitado, um símbolo.
        """
        if length < 8:
            raise ValueError("O comprimento mínimo recomendado para a senha é de 8 caracteres.")

        groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
        if use_symbols:
            groups.append(PASSWORD_SYMBOLS)
        alphabet = "".join(groups)

        # Rejeitar candidatos inteiros preserva a uniformidade entre senhas válidas.
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            if all(any(char in group for char in password) for group in groups):
                return password
