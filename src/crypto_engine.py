"""
crypto_engine.py
----------------
Módulo responsável pelas primitivas criptográficas do Vault:
- KDF: Argon2id (RFC 9106)
- AEAD: AES-256-GCM
- CSPRNG: os.urandom / secrets
- Sanitização de memória: sobrescrita forçada de buffers mutáveis (bytearrays)
"""

import os
import ctypes
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

# --- Constantes Criptográficas ---
MAGIC_BYTES = b"SECVAULT"      # 8 bytes de identificador do formato
FORMAT_VERSION = 1             # 1 byte de versão do cabeçalho
SALT_LEN = 16                  # 128 bits para o salt da KDF (Argon2id)
NONCE_LEN = 12                 # 96 bits recomendados pelo NIST SP 800-38D para GCM
KEY_LEN = 32                   # 256 bits para AES-256

# Parâmetros recomendados pelo OWASP / RFC 9106 para Argon2id
ARGON2_TIME_COST = 3           # Número de iterações
ARGON2_MEMORY_COST = 65536     # 64 MiB de consumo de RAM
ARGON2_PARALLELISM = 4         # Número de threads paralelas


def secure_zero_memory(target: bytearray) -> None:
    """
    Sobrescreve a memória de um bytearray mutável com zeros utilizando ctypes.
    Mitiga ataques de inspeção de memória em tempo de execução ou pós-despejo (core dump).
    """
    if not isinstance(target, bytearray):
        raise TypeError("A sanitização requer um objeto mutável do tipo 'bytearray'.")
    if len(target) == 0:
        return
    offset = (ctypes.c_char * len(target)).from_buffer(target)
    ctypes.memset(offset, 0, len(target))


def derive_key(master_password: str, salt: bytes) -> bytearray:
    """
    Deriva uma chave simétrica de 256 bits a partir de uma senha mestra usando Argon2id.
    Retorna a chave dentro de um bytearray para permitir sanitização posterior.
    """
    if len(salt) != SALT_LEN:
        raise ValueError(f"O salt deve ter exatamente {SALT_LEN} bytes.")

    pwd_bytes = bytearray(master_password.encode("utf-8"))
    try:
        kdf = Argon2id(
            salt=salt,
            length=KEY_LEN,
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
            ad=None,
            secret=None
        )
        derived = kdf.derive(bytes(pwd_bytes))
        return bytearray(derived)
    finally:
        # Destrói a cópia em memória da senha mestra codificada em bytes
        secure_zero_memory(pwd_bytes)


def encrypt_payload(plaintext: bytes, key: bytearray) -> Tuple[bytes, bytes]:
    """
    Cifra o payload com AES-256-GCM.
    Retorna uma tupla: (nonce, ciphertext_com_tag).
    Garante o uso de CSPRNG (os.urandom) para um nonce único de 96 bits.
    """
    if len(key) != KEY_LEN:
        raise ValueError(f"Chave AES inválida: esperado {KEY_LEN} bytes.")

    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(bytes(key))
    
    # Associated Data (AD): Vinculamos os metadados do cabeçalho como dados autenticados
    ad = MAGIC_BYTES + FORMAT_VERSION.to_bytes(1, byteorder="big")
    ciphertext = aesgcm.encrypt(nonce, plaintext, ad)
    
    return nonce, ciphertext


def decrypt_payload(nonce: bytes, ciphertext: bytes, key: bytearray) -> bytes:
    """
    Autentica e decifra o payload usando AES-256-GCM.
    Lança InvalidTag caso o arquivo tenha sido adulterado ou a chave esteja incorreta.
    """
    if len(key) != KEY_LEN:
        raise ValueError(f"Chave AES inválida: esperado {KEY_LEN} bytes.")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"Nonce inválido: esperado {NONCE_LEN} bytes.")

    aesgcm = AESGCM(bytes(key))
    ad = MAGIC_BYTES + FORMAT_VERSION.to_bytes(1, byteorder="big")
    
    # O método decrypt verifica a integridade do Authentication Tag de 128 bits em tempo constante
    return aesgcm.decrypt(nonce, ciphertext, ad)


def pack_vault_file(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Monta o binário do cofre para armazenamento em disco:
    [8B MAGIC][1B VERSION][16B SALT][12B NONCE][N bytes CIPHERTEXT + 16B TAG]
    """
    header = MAGIC_BYTES + FORMAT_VERSION.to_bytes(1, byteorder="big") + salt + nonce
    return header + ciphertext


def unpack_vault_file(raw_bytes: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Faz o parsing do arquivo binário e valida o cabeçalho.
    Retorna (salt, nonce, ciphertext).
    """
    min_len = len(MAGIC_BYTES) + 1 + SALT_LEN + NONCE_LEN + 16  # Pelo menos 16B de tag GCM
    if len(raw_bytes) < min_len:
        raise ValueError("Arquivo de cofre corrompido ou truncado.")

    magic = raw_bytes[:8]
    if magic != MAGIC_BYTES:
        raise ValueError("Formato de arquivo inválido: identificador mágico não reconhecido.")

    version = raw_bytes[8]
    if version != FORMAT_VERSION:
        raise ValueError(f"Versão do formato ({version}) incompatível com este software ({FORMAT_VERSION}).")

    offset = 9
    salt = raw_bytes[offset : offset + SALT_LEN]
    offset += SALT_LEN
    
    nonce = raw_bytes[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    
    ciphertext = raw_bytes[offset:]
    return salt, nonce, ciphertext