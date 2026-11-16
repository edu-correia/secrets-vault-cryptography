# Gerenciador de Senhas Seguro com Criptografia Autenticada

**Disciplina:** Criptografia — DCC/UFMG
**Professor:** Jeroen van de Graaf  
**Equipe:**
- Eduardo Henrique dos Santos Correia — Matrícula: 2022066060
- Luiza Sodré Salgado — Matrícula: 2021035187

---

## 1. Visão Geral

Este projeto acadêmico implementa um gerenciador de credenciais local (*offline vault*). Seu objetivo principal é proteger os dados em repouso quando alguém obtém uma cópia do arquivo do cofre.

- **Adivinhação offline.** Argon2id aumenta o custo de cada tentativa. Uma frase-senha previsível ainda pode ser descoberta.
- **Adulteração em disco.** O AES-GCM detecta alterações ao abrir o cofre. Uma cópia antiga e autêntica do mesmo cofre ainda pode ser aceita.
- **Memória.** Enquanto a sessão está aberta, os registros ficam em texto claro no processo. Um terminal gravado ou um sistema comprometido também pode expor dados que o usuário revelar.

## 2. Detalhes de Implementação

### 2.1. Derivação de Chaves (KDF): Argon2id
O projeto usa **Argon2id** (RFC 9106), variante híbrida vencedora do *Password Hashing Competition*, para derivar a chave a partir da senha mestra:
- **Salt:** 16 bytes (128 bits) gerados via CSPRNG (`os.urandom`).
- **Memória (`memory_cost`):** 64 MiB (65.536 KiB) por derivação. Esse custo dificulta a execução de muitas tentativas em paralelo.
- **Iterações (`iterations`):** 3 iterações completas.
- **Paralelismo (`lanes`):** 4 threads simultâneas.
- **Saída:** Chave simétrica de 256 bits (32 bytes).

### 2.2. Cifragem Autenticada: AES-256-GCM
Utiliza o modo **AES-GCM** (Galois/Counter Mode, NIST SP 800-38D), oferecendo confidencialidade e integridade em uma única etapa:
- **Nonce:** 12 bytes (96 bits) sorteados via CSPRNG a cada cifragem.
- **Tag de Autenticação:** 16 bytes (128 bits) calculados sobre o texto cifrado.
- **Dados associados (AAD).** O identificador `SECVAULT` e a versão são passados ao AES-GCM como dados associados. O nonce é fornecido diretamente ao AES-GCM. O salt é usado pelo Argon2id para derivar a chave. Alterar o nonce ou o salt faz a autenticação falhar em condições normais.

### 2.3. Formato Binário do Cofre (`vault.enc`)
O cofre é persistido em disco com a seguinte estrutura em bytes:
```text
[0..7]   : MAGIC BYTES ("SECVAULT")  -> 8 bytes
[8]      : VERSÃO (0x01)             -> 1 byte
[9..24]  : SALT da KDF               -> 16 bytes
[25..36] : NONCE do AES-GCM          -> 12 bytes
[37..N]  : CIPHERTEXT + TAG (GCM)    -> N bytes (JSON serializado + 16B tag)
```

O programa rejeita arquivos truncados, formatos desconhecidos e versões incompatíveis. Ele também verifica se o conteúdo autenticado é JSON válido em UTF-8 e se os registros têm os campos esperados. Uma falha na autenticação do AES-GCM pode indicar senha incorreta ou adulteração.

### 2.4. Limites da limpeza de memória

`lock()` sobrescreve o `bytearray` da chave derivada e descarta as referências do cofre aos registros. O código também zera o buffer mutável da senha usado na derivação. Strings, bytes imutáveis do Python e cópias feitas pela biblioteca criptográfica podem continuar em memória.

### 2.5. Gerador de Senhas Seguras (CSPRNG)
O gerador sorteia cada posição com `secrets.choice` e descarta o candidato inteiro se faltar uma maiúscula, uma minúscula, um dígito ou, quando habilitado, um símbolo. Com isso, todas as senhas válidas de um mesmo comprimento e alfabeto têm a mesma probabilidade. O comprimento padrão é de 20 caracteres.

## 3. Estrutura do Repositório

O código fica em `src/` e os testes ficam em `tests/`:
```
secrets-vault-cryptography/
├── requirements.txt         # Dependências externas
├── README.md                # Este documento
├── src/
│   ├── crypto_engine.py     # Argon2id, AES-GCM e operações com buffers
│   ├── vault.py             # Lógica de gerenciamento do cofre e gerador CSPRNG
│   └── cli.py               # Interface de linha de comando interativa
└── tests/
    ├── __init__.py
    └── test_vault.py        # Suíte de testes automatizados de segurança
```

## 4. Instalação

Requer Python 3.10 ou superior e `cryptography` 44.0.0 ou superior, com suporte a Argon2id. A cópia usa `pyperclip`. No Linux, ela depende de uma sessão gráfica com um mecanismo de clipboard disponível, como `wl-copy` e `wl-paste` no Wayland ou `xclip` no X11.

```
# 1. Clone o repositório ou acesse a pasta raiz
cd secrets-vault-cryptography

# 2. (Opcional) Crie e ative um ambiente virtual
python3 -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# 3. Instale as dependências
pip install -r requirements.txt
```

## 5. Como Executar a Aplicação

Para iniciar o gerenciador no terminal interativo, execute a partir da raiz:

```
python src/cli.py
```

A CLI mostra o caminho do cofre ao iniciar. Por padrão, ela usa `~/.secrets-vault/vault.enc`.

A senha mestra deve ter pelo menos 15 caracteres, incluindo algum caractere que não seja espaço em branco. Prefira várias palavras escolhidas aleatoriamente. A criação do cofre pede que você confirme a senha.

No cadastro e na atualização, a CLI avalia a senha informada ou gerada antes de salvar. A classificação usa comprimento e classes de caracteres e traz sugestões para melhorar a senha. É uma avaliação heurística. Uma senha que cumpra todos os critérios ainda pode ser previsível, e a aplicação não consulta vazamentos. Você pode confirmar a senha, tentar outra ou cancelar. A opção **Atualizar senha de uma credencial** preserva o usuário e as anotações e altera apenas o registro no cofre.

A CLI oferece cópia opcional em um terminal interativo após salvar, consultar ou gerar uma senha avulsa. Ela pede confirmação antes de copiar e não exibe a senha no terminal. Outros aplicativos podem ler a área de transferência, e o histórico ou a sincronização do sistema podem reter cópias. Limpe a área de transferência após usar.

### Arquivo e backups

Em sistemas POSIX, o diretório padrão é privado (modo `0700`) e os arquivos do cofre são gravados com modo `0600`. No Windows, use uma pasta pessoal com permissões de acesso restritas. Ao passar `--vault`, escolha um diretório existente sob seu controle.

O programa grava os dados cifrados em um temporário no mesmo diretório, sincroniza seu conteúdo e então publica o arquivo completo. A criação inicial usa um link físico para impedir que outra instância sobrescreva um cofre criado no mesmo caminho. Use um sistema de arquivos que suporte links físicos. Em atualizações, a substituição é atômica. Use uma sessão por cofre para evitar que uma sobrescreva alterações da outra.

Faça backup do arquivo cifrado e proteja o acesso às cópias. Perder a senha mestra pode tornar o cofre irrecuperável. Remover uma credencial na CLI não apaga suas versões em backups, snapshots ou cópias antigas.

## 6. Execução dos Testes Automatizados

A suíte inclui testes de persistência, rejeição de senhas incorretas, detecção de adulterações, propriedades do gerador, feedback de força e sobrescrita do buffer mutável da chave. Observar nonces distintos nesses testes não demonstra unicidade absoluta.

```
python -m unittest discover -s tests -v
```
