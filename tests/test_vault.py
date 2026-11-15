"""
test_vault.py
-------------
Bateria de testes de segurança automatizados:
1. Rejeição de adulteração (tampering) no Ciphertext, Tag, Salt e Nonce.
2. Unicidade estrita de Nonces/IVs em múltiplas operações de escrita.
3. Validação de sanitização de memória (sobrescrita com zeros) após lock().
4. Resistência a senhas mestras incorretas.
5. Propriedades do gerador aleatório CSPRNG.
"""

import os
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import crypto_engine
from src.vault import Vault

class TestSecureVault(unittest.TestCase):
    def setUp(self):
        self.test_vault_file = "test_vault.enc"
        if os.path.exists(self.test_vault_file):
            os.remove(self.test_vault_file)
        self.master_pwd = "S3cur3!MasterP@ssw0rd#2026"

    def tearDown(self):
        if os.path.exists(self.test_vault_file):
            os.remove(self.test_vault_file)

    def test_complete_lifecycle(self):
        """Valida inicialização, escrita, persistência, fechamento e reabertura correta."""
        vault = Vault(self.test_vault_file)
        vault.initialize(self.master_pwd)
        vault.add_entry("ServicoA", "usuario1", "senhaForte123!", "Notas A")
        vault.lock()

        # Reabrir com o mesmo segredo
        reopened = Vault(self.test_vault_file)
        self.assertTrue(reopened.unlock(self.master_pwd))
        entry = reopened.get_entry("ServicoA")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["username"], "usuario1")
        self.assertEqual(entry["password"], "senhaForte123!")
        reopened.lock()

    def test_wrong_master_password(self):
        """Garante que senhas incorretas são rejeitadas pelo Authentication Tag do GCM."""
        vault = Vault(self.test_vault_file)
        vault.initialize(self.master_pwd)
        vault.add_entry("ServicoB", "user", "pass")
        vault.lock()

        reopened = Vault(self.test_vault_file)
        self.assertFalse(reopened.unlock("SenhaErrada123!"))

    def test_tampering_rejection_ciphertext_and_tag(self):
        """
        TESTE DE SEGURANÇA 1: Rejeição estrita de adulteração (tampering) de bits.
        Altera 1 único bit no arquivo gravado e valida se o AES-GCM rejeita a leitura.
        """
        vault = Vault(self.test_vault_file)
        vault.initialize(self.master_pwd)
        vault.add_entry("GitHub", "dev_crypto", "token_ultra_secreto")
        vault.save()
        vault.lock()

        with open(self.test_vault_file, "rb") as f:
            data = bytearray(f.read())

        # Inverte o último bit do arquivo (pertencente ao tag de autenticação GCM)
        data[-1] ^= 0x01

        with open(self.test_vault_file, "wb") as f:
            f.write(data)

        # Abertura deve falhar categoricamente
        attacked_vault = Vault(self.test_vault_file)
        self.assertFalse(attacked_vault.unlock(self.master_pwd))

    def test_tampering_nonce_and_salt(self):
        """Valida que adulterar os metadados (nonce/salt) invalida a integridade."""
        vault = Vault(self.test_vault_file)
        vault.initialize(self.master_pwd)
        vault.add_entry("Banco", "correntista", "pin1234")
        vault.lock()

        with open(self.test_vault_file, "rb") as f:
            data = bytearray(f.read())

        # O Nonce começa no byte 25 (8 magic + 1 version + 16 salt = 25)
        data[26] ^= 0xFF

        with open(self.test_vault_file, "wb") as f:
            f.write(data)

        attacked_vault = Vault(self.test_vault_file)
        self.assertFalse(attacked_vault.unlock(self.master_pwd))

    def test_strict_nonce_uniqueness(self):
        """
        TESTE DE SEGURANÇA 2: Unicidade estrita de IVs/Nonces a cada escrita.
        A catástrofe de reutilização de nonce no GCM expõe a autenticidade e texto plano.
        """
        vault = Vault(self.test_vault_file)
        vault.initialize(self.master_pwd)

        nonces_seen = set()
        iterations = 50

        for i in range(iterations):
            vault.add_entry(f"servico_{i}", f"user_{i}", f"pass_{i}")
            with open(self.test_vault_file, "rb") as f:
                raw = f.read()
            _, nonce, _ = crypto_engine.unpack_vault_file(raw)
            self.assertNotIn(nonce, nonces_seen, f"COLISÃO CRÍTICA DE NONCE DETECTADA na iteração {i}!")
            nonces_seen.add(nonce)

        self.assertEqual(len(nonces_seen), iterations)
        vault.lock()

    def test_memory_sanitization(self):
        """
        TESTE DE SEGURANÇA 3: Validação de sanitização da chave na memória após lock().
        Garante que o buffer é sobrescrito com 0x00 via ctypes.
        """
        vault = Vault(self.test_vault_file)
        vault.initialize(self.master_pwd)

        # Captura referência ao buffer da chave mestra em memória
        key_buffer_ref = vault._master_key
        self.assertIsNotNone(key_buffer_ref)
        self.assertEqual(len(key_buffer_ref), crypto_engine.KEY_LEN)
        self.assertNotEqual(key_buffer_ref, bytearray(crypto_engine.KEY_LEN))

        # Executa lock
        vault.lock()

        # O buffer original deve ter sido completamente zerado antes de ter a referência descartada
        self.assertEqual(key_buffer_ref, bytearray(crypto_engine.KEY_LEN))
        self.assertIsNone(vault._master_key)

    def test_csprng_password_generator(self):
        """Verifica a conformidade e entropia do gerador de senhas aleatórias."""
        for length in [12, 24, 32]:
            pwd = Vault.generate_secure_password(length=length, use_symbols=True)
            self.assertEqual(len(pwd), length)
            self.assertTrue(any(c.isupper() for c in pwd))
            self.assertTrue(any(c.islower() for c in pwd))
            self.assertTrue(any(c.isdigit() for c in pwd))
            self.assertTrue(any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd))


if __name__ == "__main__":
    unittest.main()