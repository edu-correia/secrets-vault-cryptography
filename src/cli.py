"""
cli.py
------
Interface interativa de linha de comando (CLI) para o Gerenciador de Senhas Seguro.
Oferece menus para inicializar, autenticar, adicionar, buscar, listar, gerar senhas e trancar.
"""

import sys
import getpass

try:
    from src.vault import Vault
except ImportError:
    from vault import Vault

def prompt_master_password(confirm: bool = False) -> str:
    pwd = getpass.getpass("Digite a senha mestra: ")
    if confirm:
        pwd2 = getpass.getpass("Confirme a senha mestra: ")
        if pwd != pwd2:
            print("[ERRO] As senhas digitadas não coincidem!")
            sys.exit(1)
    if len(pwd) < 8:
        print("[AVISO] Senha mestra fraca! Recomendamos pelo menos 12 caracteres com boa entropia.")
    return pwd


def interactive_menu(vault: Vault):
    while True:
        print("\n" + "=" * 45)
        print("    GERENCIADOR DE SENHAS SEGURO (AES-GCM)")
        print("=" * 45)
        print("1. Cadastrar nova credencial")
        print("2. Consultar credencial")
        print("3. Listar serviços cadastrados")
        print("4. Remover credencial")
        print("5. Gerar senha aleatória (CSPRNG)")
        print("6. Trancar sessão e sair")
        opcao = input("\nEscolha uma opção [1-6]: ").strip()

        if opcao == "1":
            svc = input("Nome do serviço (ex: GitHub, Gmail): ").strip()
            usr = input("Nome de usuário / e-mail: ").strip()
            gen = input("Deseja gerar uma senha aleatória segura? (s/N): ").strip().lower()
            if gen == "s":
                pwd = Vault.generate_secure_password(length=20)
                print(f"[OK] Senha gerada com sucesso: {pwd}")
            else:
                pwd = getpass.getpass("Digite a senha do serviço: ")
            notes = input("Anotações adicionais (opcional): ").strip()

            vault.add_entry(svc, usr, pwd, notes)
            print(f"[SUCESSO] Credencial para '{svc}' armazenada com integridade verificada!")

        elif opcao == "2":
            svc = input("Digite o nome do serviço a consultar: ").strip()
            entry = vault.get_entry(svc)
            if entry:
                print("\n--- DETALHES DA CREDENCIAL ---")
                print(f"Serviço    : {entry['service_name']}")
                print(f"Usuário    : {entry['username']}")
                print(f"Senha      : {entry['password']}")
                print(f"Anotações  : {entry['notes']}")
                print(f"Atualizado : {entry['updated_at']}")
            else:
                print(f"[INFO] Nenhum registro encontrado para '{svc}'.")

        elif opcao == "3":
            services = vault.list_services()
            print(f"\n--- SERVIÇOS CADASTRADOS ({len(services)}) ---")
            if not services:
                print("Nenhum serviço cadastrado.")
            for s in services:
                print(f"- {s}")

        elif opcao == "4":
            svc = input("Digite o nome do serviço a remover: ").strip()
            confirm = input(f"Tem certeza que deseja apagar '{svc}'? (s/N): ").strip().lower()
            if confirm == "s":
                if vault.delete_entry(svc):
                    print(f"[SUCESSO] Registro de '{svc}' removido com sucesso.")
                else:
                    print(f"[ERRO] Serviço '{svc}' não encontrado.")

        elif opcao == "5":
            try:
                tam = int(input("Comprimento da senha [padrão: 20]: ") or "20")
                nova_senha = Vault.generate_secure_password(length=tam)
                print(f"\n[SENHA GERADA]: {nova_senha}")
            except ValueError as e:
                print(f"[ERRO] Entrada inválida: {e}")

        elif opcao == "6":
            vault.lock()
            print("\n[OK] Memória sanitizada e cofre trancado com segurança. Até logo!")
            break
        else:
            print("[ERRO] Opção inválida. Tente novamente.")


def main():
    vault_file = "vault.enc"
    vault = Vault(filepath=vault_file)

    print("==================================================")
    print("   SECURE VAULT — DCC/ICEx/UFMG (Criptografia)    ")
    print("==================================================")

    if not vault.is_initialized():
        print("[INFO] Nenhum cofre existente detectado.")
        cria = input("Deseja criar um novo cofre agora? (S/n): ").strip().lower()
        if cria in ("n", "nao", "não"):
            print("Operação cancelada.")
            return

        pwd = prompt_master_password(confirm=True)
        print("[AGUARDE] Derivando chave com Argon2id (custo de memória e tempo elevado)...")
        vault.initialize(pwd)
        print("[SUCESSO] Cofre criado e autenticado com sucesso!")
    else:
        print("[INFO] Cofre cifrado detectado.")
        pwd = prompt_master_password(confirm=False)
        print("[AGUARDE] Verificando integridade e derivando chave...")
        sucesso = vault.unlock(pwd)
        if not sucesso:
            print("\n[ERRO CRÍTICO] Falha de autenticação!")
            print("Causa provável: Senha mestra incorreta ou arquivo adulterado (tampering).")
            sys.exit(1)
        print("[SUCESSO] Cofre desbloqueado com autenticidade verificada!")

    try:
        interactive_menu(vault)
    except KeyboardInterrupt:
        print("\n[INTERRUPÇÃO] Finalizando imediatamente...")
        vault.lock()
        print("[OK] Memória limpa.")


if __name__ == "__main__":
    main()