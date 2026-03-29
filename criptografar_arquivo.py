import os
import re
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import secrets

SALT_SIZE = 16  # bytes
KEY_SIZE = 32   # 256-bit AES


def validar_senha(senha: str) -> tuple[bool, str]:
    """Valida os requisitos de senha:
    - 1 letra maiúscula
    - 1 número
    - 1 caracter especial
    - 8 a 16 caracteres
    """
    if len(senha) < 8 or len(senha) > 16:
        return False, "A senha deve ter entre 8 e 16 caracteres."

    if not re.search(r"[A-Z]", senha):
        return False, "A senha deve conter pelo menos uma letra maiúscula."

    if not re.search(r"[0-9]", senha):
        return False, "A senha deve conter pelo menos um número."

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", senha):
        return False, "A senha deve conter pelo menos um caracter especial."

    return True, "Senha válida."


def obter_senha(confirmar: bool = False) -> bytes:
    while True:
        senha = getpass("Digite a senha (8-16, 1 maiúscula, 1 número, 1 especial): ")
        valido, msg = validar_senha(senha)
        if not valido:
            print(f"Senha inválida: {msg}")
            continue

        if confirmar:
            confirmacao = getpass("Confirme a senha: ")
            if senha != confirmacao:
                print("As senhas não coincidem. Tente novamente.")
                continue

        return senha.encode('utf-8')


def derivar_chave(senha: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(senha)


def listar_arquivos(pasta: str) -> list[str]:
    if not os.path.isdir(pasta):
        raise FileNotFoundError(f"Pasta não encontrada: {pasta}")

    return [
        os.path.join(pasta, f)
        for f in os.listdir(pasta)
        if os.path.isfile(os.path.join(pasta, f))
    ]


def criptografar_arquivo(caminho: str, senha: bytes) -> bytes:
    with open(caminho, "rb") as f:
        dados = f.read()

    padder = padding.PKCS7(128).padder()
    dados_padded = padder.update(dados) + padder.finalize()

    salt = secrets.token_bytes(SALT_SIZE)
    iv = secrets.token_bytes(16)
    chave = derivar_chave(senha, salt)

    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    dados_criptografados = encryptor.update(dados_padded) + encryptor.finalize()

    return salt + iv + dados_criptografados


def salvar_criptografado(conteudo: bytes, caminho_original: str, pasta_backup: str) -> None:
    os.makedirs(pasta_backup, exist_ok=True)
    nome_arquivo = os.path.basename(caminho_original) + ".enc"
    destino = os.path.join(pasta_backup, nome_arquivo)
    with open(destino, "wb") as f:
        f.write(conteudo)
    print(f"  ✔ Salvo: {destino}")


def descriptografar_arquivo(caminho: str, senha: bytes) -> bytes:
    with open(caminho, "rb") as f:
        conteudo = f.read()

    salt = conteudo[:SALT_SIZE]
    iv = conteudo[SALT_SIZE:SALT_SIZE + 16]
    dados = conteudo[SALT_SIZE + 16:]

    chave = derivar_chave(senha, salt)

    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dados_padded = decryptor.update(dados) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(dados_padded) + unpadder.finalize()


def salvar_descriptografado(conteudo: bytes, caminho_enc: str, pasta_saida: str) -> None:
    os.makedirs(pasta_saida, exist_ok=True)
    nome_original = os.path.basename(caminho_enc).removesuffix(".enc")
    destino = os.path.join(pasta_saida, nome_original)
    with open(destino, "wb") as f:
        f.write(conteudo)
    print(f"  ✔ Restaurado: {destino}")


def menu() -> str:
    print("\n=== Criptografia AES de Arquivos ===")
    print("1. Criptografar arquivos")
    print("2. Descriptografar arquivos")
    print("0. Sair")
    return input("Escolha: ").strip()


def main() -> None:
    while True:
        opcao = menu()

        if opcao == "1":
            pasta_original = input("Pasta com os arquivos originais: ").strip()
            pasta_backup = "/home/leo/fiap/machine_learning/criptografados"
            print(f"Saída fixada em: {pasta_backup}")

            try:
                senha = obter_senha(confirmar=True)
                arquivos = listar_arquivos(pasta_original)

                if not arquivos:
                    print("Nenhum arquivo encontrado na pasta.")
                    continue

                print(f"\nCriptografando {len(arquivos)} arquivo(s)...")
                for caminho in arquivos:
                    conteudo = criptografar_arquivo(caminho, senha)
                    salvar_criptografado(conteudo, caminho, pasta_backup)
                print("Concluído!")

            except (ValueError, FileNotFoundError) as e:
                print(f"Erro: {e}")

        elif opcao == "2":
            pasta_enc = input("Pasta com os arquivos criptografados (.enc): ").strip()
            pasta_saida = "/home/leo/fiap/machine_learning/descriptografados"
            print(f"Saída fixada em: {pasta_saida}")

            try:
                senha = obter_senha()
                arquivos = listar_arquivos(pasta_enc)
                arquivos = [a for a in arquivos if a.endswith(".enc")]

                if not arquivos:
                    print("Nenhum arquivo .enc encontrado.")
                    continue

                print(f"\nDescriptografando {len(arquivos)} arquivo(s)...")
                for caminho in arquivos:
                    try:
                        conteudo = descriptografar_arquivo(caminho, senha)
                        salvar_descriptografado(conteudo, caminho, pasta_saida)
                    except Exception:
                        print(f"  ✘ Falha em {caminho} — senha incorreta ou arquivo corrompido.")
                print("Concluído!")

            except FileNotFoundError as e:
                print(f"Erro: {e}")

        elif opcao == "0":
            print("Encerrando.")
            break

        else:
            print("Opção inválida.")


if __name__ == "__main__":
    main()
