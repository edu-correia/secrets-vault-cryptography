# Gerenciador de Senhas Seguro com Criptografia Autenticada

**Disciplina:** Criptografia — DCC/UFMG
**Professor:** Jeroen van de Graaf  
**Equipe:**
- Eduardo Henrique dos Santos Correia — Matrícula: 2022066060
- Luiza Sodré Salgado — Matrícula: 2021035187

---

## 1. Visão Geral

Este projeto consiste na implementação de um gerenciador de credenciais local (*offline vault*) focado em segurança criptográfica em repouso (*at-rest*) e na contenção de superfícies de ataque reais:

- **Força bruta offline (GPU/ASIC):** Dificultada via KDF *memory-hard* moderna.
- **Adulteração maliciosa em disco (*tampering*):** Prevenida por meio de cifragem autenticada com detecção de alteração de bits em tempo constante.
- **Reutilização de Nonce/IV:** Mitigada garantindo a geração de vetores estritamente novos a cada operação de escrita.
- **Inspeção de memória (*RAM dump*):** Mitigada via sobrescrita forçada de chaves e buffers sensíveis ao trancar a sessão.

## 2. Detalhes de Implementação

### 2.1. Derivação de Chaves (KDF): Argon2id
Em vez de funções legadas suscetíveis à aceleração em silício (como PBKDF2), o projeto adota o **Argon2id** (RFC 9106), variante híbrida vencedora do *Password Hashing Competition*:
- **Salt:** 16 bytes (128 bits) gerados via CSPRNG (`os.urandom`).
- **Memória (`memory_cost`):** 64 MiB (65.536 KiB) por derivação, impondo um custo de RAM inviável para paralelização massiva em placas de vídeo.
- **Iterações (`iterations`):** 3 iterações completas.
- **Paralelismo (`lanes`):** 4 threads simultâneas.
- **Saída:** Chave simétrica de 256 bits (32 bytes).

### 2.2. Cifragem Autenticada: AES-256-GCM
Utiliza o modo **AES-GCM** (Galois/Counter Mode, NIST SP 800-38D), oferecendo confidencialidade e integridade em uma única etapa:
- **Nonce:** 12 bytes (96 bits) colhidos de CSPRNG a cada salvamento do cofre.
- **Tag de Autenticação:** 16 bytes (128 bits) calculados sobre o texto cifrado.
- **Dados Associados Autenticados (AD):** O cabeçalho fixo (`SECVAULT` + versão) é amarrado como *Associated Data*. Qualquer alteração no cabeçalho invalida a decifragem.

### 2.3. Formato Binário do Cofre (`vault.enc`)
O cofre é persistido em disco com a seguinte estrutura em bytes:
```text
[0..7]   : MAGIC BYTES ("SECVAULT")  -> 8 bytes
[8]      : VERSÃO (0x01)             -> 1 byte
[9..24]  : SALT da KDF               -> 16 bytes
[25..36] : NONCE do AES-GCM          -> 12 bytes
[37..N]  : CIPHERTEXT + TAG (GCM)    -> N bytes (JSON serializado + 16B tag)
```

### 2.4. Sanitização de Memória Volátil
Em decorrência do Garbage Collector e da imutabilidade das strings no CPython, as chaves mestras e dados sensíveis são gerenciados como bytearray mutáveis. A função secure_zero_memory() utiliza ctypes.memset para preencher o bloco físico de memória com zeros (0x00) no instante em que o método vault.lock() é invocado.

### 2.5. Gerador de Senhas Seguras (CSPRNG)
O gerador embutido utiliza a biblioteca padrão secrets do Python e aplica o algoritmo de embaralhamento de Fisher-Yates, assegurando a inclusão de pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial sem introduzir viés estatístico.

## 3. Estrutura do Repositório

O projeto adota o padrão canônico src-layout, mantendo os testes isolados do código de produção:
```
secrets-vault-cryptography/
├── requirements.txt         # Dependências externas
├── README.md                # Este documento
├── src/
│   ├── __init__.py
│   ├── crypto_engine.py     # Primitivas criptográficas (Argon2id, AES-GCM, ctypes)
│   ├── vault.py             # Lógica de gerenciamento do cofre e gerador CSPRNG
│   └── cli.py               # Interface de linha de comando interativa
└── tests/
    ├── __init__.py
    └── test_vault.py        # Suíte de testes automatizados de segurança
```

## 4. Instalação

Requisitos: Python 3.10 ou superior.

```
# 1. Clone o repositório ou acesse a pasta raiz
cd secrets-vault-cryptography

# 2. (Opcional) Crie e ative um ambiente virtual
python3 -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# 3. Instale a biblioteca de suporte criptográfico
pip install -r requirements.txt
```

## 5. Como Executar a Aplicação

Para iniciar o gerenciador no terminal interativo, execute a partir da raiz:

```
python src/cli.py
```

## 6. Execução dos Testes Automatizados

A bateria de testes cobre todos os requisitos de segurança acordados na proposta do projeto:

```
python -m unittest discover -s tests -v
```