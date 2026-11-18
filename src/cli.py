"""
cli.py
------
Interface interativa de linha de comando (CLI) para o Gerenciador de Senhas Seguro.
Oferece menus para inicializar, autenticar, adicionar, buscar, listar, gerar senhas e trancar.
"""

import argparse
import base64
import getpass
import os
import shutil
import stat
import subprocess
import sys
import warnings
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm

try:
    from src.vault import Vault, VaultFormatError
except ImportError:
    from vault import Vault, VaultFormatError


def read_secret(prompt: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def prompt_master_password(confirm: bool = False) -> str:
    prompt = "Digite a nova senha mestra: " if confirm else "Digite a senha mestra: "
    while True:
        pwd = read_secret(prompt)
        try:
            Vault.validate_master_password(pwd)
        except ValueError as exc:
            print(f"[ERRO] {exc}")
            continue
        if not confirm or pwd == read_secret("Confirme a senha mestra: "):
            return pwd
        print("[ERRO] As senhas digitadas não coincidem.")


def copy_to_clipboard(text: str) -> tuple[bool, str]:
    """
    Copia o texto para a área de transferência usando o utilitário adequado.
    Alimenta o processo exclusivamente via stdin para impedir vazamento de senhas
    na tabela de processos do sistema operacional (ps aux).
    """
    payload = text.encode("utf-8")

    # 1. Wayland nativo (Padrão no Ubuntu 22.04)
    if os.getenv("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        try:
            subprocess.run(["wl-copy"], input=payload, check=True, stdout=subprocess.DEVNULL)
            return True, "Senha copiada via wl-copy (Wayland)."
        except (subprocess.SubprocessError, OSError):
            pass

    # 2. X11 / XWayland via xclip
    if os.getenv("DISPLAY") and shutil.which("xclip"):
        try:
            subprocess.run(
                ["xclip", "-selection", "clipboard"],
                input=payload,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            return True, "Senha copiada via xclip (X11)."
        except (subprocess.SubprocessError, OSError):
            pass

    # 3. X11 / XWayland via xsel
    if os.getenv("DISPLAY") and shutil.which("xsel"):
        try:
            subprocess.run(
                ["xsel", "--clipboard", "--input"],
                input=payload,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            return True, "Senha copiada via xsel (X11)."
        except (subprocess.SubprocessError, OSError):
            pass

    # 4. macOS
    if sys.platform == "darwin" and shutil.which("pbcopy"):
        try:
            subprocess.run(["pbcopy"], input=payload, check=True)
            return True, "Senha copiada via pbcopy."
        except (subprocess.SubprocessError, OSError):
            pass

    # 5. Windows
    if sys.platform == "win32" and shutil.which("clip"):
        try:
            subprocess.run(["clip"], input=payload, check=True)
            return True, "Senha copiada via clip.exe."
        except (subprocess.SubprocessError, OSError):
            pass

    # 6. Fallback: pyperclip (caso instalado e configurado)
    try:
        import pyperclip

        pyperclip.copy(text)
        return True, "Senha copiada via pyperclip."
    except Exception:
        pass

    # 7. Fallback: Tkinter (caso python3-tk esteja presente no sistema)
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.destroy()
        return True, "Senha copiada via interface gráfica (Tkinter)."
    except Exception:
        pass

    # 8. Fallback: Sequência de escape de terminal OSC 52 (VS Code, Kitty, Alacritty, etc.)
    if sys.stdout.isatty():
        try:
            b64 = base64.b64encode(payload).decode("ascii")
            sys.stdout.write(f"\033]52;c;{b64}\a")
            sys.stdout.flush()
            # Retorna sucesso mas alerta caso o terminal não interprete OSC 52
            return True, "Senha enviada ao terminal via OSC 52."
        except Exception:
            pass

    # Diagnóstico específico para Linux
    if sys.platform.startswith("linux"):
        is_wayland = bool(os.getenv("WAYLAND_DISPLAY"))
        recommended_pkg = "wl-clipboard" if is_wayland else "xclip"
        msg = (
            "Nenhum utilitário de área de transferência encontrado.\n"
            f"No Ubuntu/Debian, instale executando:\n"
            f"    sudo apt install {recommended_pkg}\n"
            "    (ou: sudo apt install wl-clipboard xclip)"
        )
        return False, msg

    return False, "Área de transferência indisponível nesta sessão."


def offer_password_copy(password: str) -> None:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("[INFO] Cópia disponível apenas em um terminal interativo.")
        return
    print(
        "[AVISO] Outros aplicativos podem ler a área de transferência. "
        "O histórico ou a sincronização do sistema podem conservar uma cópia."
    )
    if input("Copiar a senha para a área de transferência? (s/N): ").strip().lower() != "s":
        return

    success, message = copy_to_clipboard(password)
    if success:
        print(f"[OK] {message} Limpe a área de transferência após usar.")
    else:
        print(f"[ERRO] {message}", file=sys.stderr)


def choose_password() -> str | None:
    while True:
        if input("Gerar uma senha aleatória? (s/N): ").strip().lower() == "s":
            password = Vault.generate_secure_password()
        else:
            password = read_secret("Digite a senha do serviço: ")

        level, suggestions = Vault.check_password_strength(password)
        print(f"Força estimada: {level}")
        for suggestion in suggestions:
            print(f"- {suggestion}")

        while True:
            action = input("[s] Usar esta senha, [t] Tentar outra, [Enter] Cancelar: ").strip().lower()
            if action == "s":
                return password
            if not action:
                return None
            if action == "t":
                break
            print("[ERRO] Opção inválida.")


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
        print("7. Atualizar senha de uma credencial")
        opcao = input("\nEscolha uma opção [1-7]: ").strip()

        if opcao == "1":
            svc = input("Nome do serviço (ex: GitHub, Gmail): ").strip()
            usr = input("Nome de usuário / e-mail: ").strip()
            pwd = choose_password()
            if pwd is None:
                continue
            notes = input("Anotações adicionais (opcional): ").strip()

            vault.add_entry(svc, usr, pwd, notes)
            print(f"[SUCESSO] Credencial para '{svc}' armazenada no cofre.")
            offer_password_copy(pwd)
            del pwd

        elif opcao == "2":
            svc = input("Digite o nome do serviço a consultar: ").strip()
            entry = vault.get_entry(svc)
            if entry:
                print("\n--- DETALHES DA CREDENCIAL ---")
                print(f"Serviço    : {entry['service_name']}")
                print(f"Usuário    : {entry['username']}")
                print("Senha      : [oculta]")
                print(f"Anotações  : {entry['notes']}")
                print(f"Atualizado : {entry['updated_at']}")
                offer_password_copy(entry["password"])
                del entry
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
                if not 8 <= tam <= 1024:
                    raise ValueError("Use um comprimento entre 8 e 1024 caracteres.")
                nova_senha = Vault.generate_secure_password(length=tam)
            except ValueError:
                print("[ERRO] Informe um comprimento inteiro entre 8 e 1024 caracteres.")
            else:
                print("[OK] Senha gerada para uso avulso.")
                offer_password_copy(nova_senha)
                del nova_senha

        elif opcao == "6":
            break
        elif opcao == "7":
            svc = input("Digite o nome do serviço a atualizar: ").strip()
            entry = vault.get_entry(svc)
            if entry is None:
                print(f"[INFO] Nenhum registro encontrado para '{svc}'.")
                continue

            print(
                "[INFO] Esta alteração atualiza apenas o cofre. "
                "Altere a senha também no serviço, se necessário."
            )
            pwd = choose_password()
            if pwd is not None:
                vault.add_entry(entry["service_name"], entry["username"], pwd, entry["notes"])
                print("[OK] Senha atualizada no cofre.")
                offer_password_copy(pwd)
            del entry, pwd
        else:
            print("[ERRO] Opção inválida. Tente novamente.")


def default_vault_path() -> Path:
    directory = Path.home() / ".secrets-vault"
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise PermissionError("O diretório padrão do cofre não pode ser um link simbólico.")
    if os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise PermissionError("O diretório padrão deve pertencer ao usuário e ter modo 0700.")
    return directory / "vault.enc"


def run_vault(vault: Vault) -> int:
    print("==================================================")
    print("   SECURE VAULT — DCC/ICEx/UFMG (Criptografia)    ")
    print("==================================================")
    print(f"Arquivo do cofre: {vault.filepath}")

    if not vault.is_initialized():
        print("[INFO] Nenhum cofre existente detectado.")
        cria = input("Deseja criar um novo cofre agora? (s/N): ").strip().lower()
        if cria != "s":
            print("Operação cancelada.")
            return 0

        pwd = prompt_master_password(confirm=True)
        try:
            print("[AGUARDE] Derivando chave com Argon2id...")
            vault.initialize(pwd)
        finally:
            del pwd
        print("[SUCESSO] Cofre criado e desbloqueado.")
    else:
        print("[INFO] Cofre cifrado detectado.")
        if not vault.unlock(prompt_master_password()):
            print(
                "[ERRO] Falha de autenticação. Verifique a senha mestra e o arquivo do cofre.",
                file=sys.stderr,
            )
            return 1
        print("[SUCESSO] Cofre desbloqueado com autenticidade verificada!")

    interactive_menu(vault)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Gerenciador local de senhas.")
    parser.add_argument("--vault", type=Path, help="Caminho para um cofre existente ou novo.")
    args = parser.parse_args()
    vault = None
    try:
        path = args.vault.expanduser().absolute() if args.vault else default_vault_path()
        vault = Vault(filepath=path)
        return run_vault(vault)
    except VaultFormatError as exc:
        print(f"[ERRO] Não foi possível abrir o cofre. {exc}", file=sys.stderr)
    except OSError as exc:
        print(f"[ERRO] Falha no acesso ao cofre. {exc.strerror or exc}", file=sys.stderr)
    except getpass.GetPassWarning:
        print("[ERRO] A entrada de senha requer um terminal com eco desativado.", file=sys.stderr)
    except UnicodeEncodeError:
        print("[ERRO] A entrada contém caracteres incompatíveis com UTF-8.", file=sys.stderr)
    except UnsupportedAlgorithm:
        print("[ERRO] A instalação de cryptography não oferece suporte a Argon2id.", file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print("\n[INFO] Sessão encerrada.")
        return 130
    finally:
        if vault is not None:
            was_unlocked = vault.is_unlocked
            vault.lock()
            if was_unlocked:
                print("[OK] Cofre trancado.")
    return 1


if __name__ == "__main__":
    sys.exit(main())