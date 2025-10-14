# Resolver Recursivo Validante com Cache e DNSSEC

**Redes de Computadores - Trabalho 1**
**Professor:** Irineu Sotoma
**Autores:** Caio K. F. Mendes, Marcus Augusto F. Madureira, Mariana C. Piccini

---

## Compilação

Para compilar o projeto, siga os passos abaixo.

### 1. Pré-requisitos (Ambientes Linux/Debian/Ubuntu)

Certifique-se de ter o compilador `gcc`, as bibliotecas de desenvolvimento OpenSSL e as ferramentas de DNS (como `dig`) instaladas. Você pode instalar tudo com o seguinte comando:

```bash
sudo apt update && sudo apt install build-essential libssl-dev bind9-dnsutils -y
```

### 2. Compilando com `make`

Com os pré-requisitos instalados, navegue até a pasta raiz do projeto (onde o `Makefile` se encontra) e execute o comando:

```bash
make
```

Este comando irá:
1.  Criar um diretório `build/` para armazenar os arquivos-objeto (`.o`).
2.  Compilar todos os arquivos-fonte do diretório `src/`.
3.  Gerar os executáveis `dns_resolver` e `cache_daemon` no diretório raiz do projeto.

### 3. Limpando os Arquivos Gerados

Para remover os executáveis e o diretório `build/`, utilize o comando:

```bash
make clean
```

### Nota para Usuários Windows

É recomendado utilizar o **Subsistema Windows para Linux (WSL)**. Para instalá-lo, abra o PowerShell como administrador e execute:

```bash
wsl --install
```

Após a instalação e configuração de uma distribuição Linux (como o Ubuntu), siga os mesmos passos de compilação acima dentro do terminal do WSL.

---

## Roteiro de Execução e Testes

O roteiro a seguir demonstra as principais funcionalidades do sistema. Execute todos os comandos a partir do diretório raiz do projeto.

### 1. Ativação e Verificação Inicial do Daemon

Iniciamos o processo do daemon de cache, verificamos seu status e garantimos que os caches comecem vazios para um teste limpo.

```bash
# Ativa o daemon em segundo plano
./cache_daemon --activate

# Verifica o status e o tamanho dos caches
./cache_daemon --status

# Limpa qualquer registro preexistente
./cache_daemon --purge all

# Lista os caches para confirmar que estão vazios
./cache_daemon --list all
```

### 2. Teste de Cache Positivo (Cache Miss e Cache Hit)

A primeira consulta força a resolução completa (`cache miss`), enquanto a segunda deve ser respondida instantaneamente pelo cache (`cache hit`).

```bash
# 1ª execução: O resolver busca a informação na rede (CACHE MISS)
./dns_resolver --name www.ufms.br --qtype A --trace

# 2ª execução: A resposta vem diretamente do cache (CACHE HIT)
./dns_resolver --name www.ufms.br --qtype A --trace
```

### 3. Verificação do Conteúdo do Cache Positivo

Listamos o cache para confirmar que o registro de `www.ufms.br` foi armazenado com sucesso.

```bash
./cache_daemon --list all
```

### 4. Teste de Cache Negativo (NXDOMAIN)

Consultamos um domínio que não existe. A primeira vez, o sistema descobre isso na rede; na segunda, o cache negativo nos dá a resposta.

```bash
# 1ª execução: O resolver recebe um NXDOMAIN da rede
./dns_resolver --name inexistente.naotemdns --qtype A --trace

# 2ª execução: A resposta NXDOMAIN vem do cache negativo
./dns_resolver --name inexistente.naotemdns --qtype A --trace
```

### 5. Verificação do Conteúdo do Cache Negativo

Além da entrada positiva anterior, a lista de cache negativo agora deve conter o registro para `inexistente.naotemdns`.

```bash
./cache_daemon --list all
```

### 6. Teste da Interface de Gerenciamento do Daemon

Validamos a funcionalidade de gerenciamento, alterando o tamanho máximo dos caches e confirmando a alteração.

```bash
# Altera o tamanho máximo do cache positivo para 100
./cache_daemon --set positive 100

# Altera o tamanho máximo do cache negativo para 20
./cache_daemon --set negative 20

# Confirma que os novos limites foram aplicados
./cache_daemon --status
```

### 7. Testando a Funcionalidade DNSSEC (Bônus)

A validação DNSSEC adiciona uma camada de segurança às consultas, e seu funcionamento depende de uma **Âncora de Confiança** (`Trust Anchor`). Este é um arquivo contendo as chaves públicas da zona raiz do DNS, a partir do qual a cadeia de confiança é validada.

**Passo 1: Gerar o arquivo de âncoras (`root.keys`)**

Antes de executar uma consulta com validação, é necessário obter as chaves públicas da raiz do DNS. Execute o comando abaixo no terminal para criar o arquivo `root.keys`:

```bash
# O comando consulta diretamente um servidor raiz para obter as chaves DNSKEY
dig @a.root-servers.net . DNSKEY +multiline > root.keys
```
**Importante:** Este arquivo `root.keys` deve ser entregue junto com o código-fonte do projeto.

**Passo 2: Executar uma consulta com o parâmetro `--trust-anchor`**

Com o arquivo `root.keys` no mesmo diretório, você pode instruir o resolver a usá-lo para a validação DNSSEC.

```bash
# Exemplo de consulta para um domínio que usa DNSSEC
./dns_resolver --name www.nic.cz --qtype A --trust-anchor root.keys --trace
```
*Nota: A implementação atual carrega a âncora de confiança para a memória. A validação completa da cadeia criptográfica (DS -> DNSKEY -> RRSIG) é um requisito bônus do trabalho.*

### 8. Desativação do Daemon

Ao final de todos os testes, limpamos os caches e encerramos o processo do daemon de forma controlada.

```bash
# Limpa todos os caches
./cache_daemon --purge all

# Desativa o daemon
./cache_daemon --deactivate
```