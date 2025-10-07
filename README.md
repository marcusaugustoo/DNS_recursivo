# Resolvedor DNS Iterativo em C

Este é um projeto para a disciplina de Redes de Computadores que implementa um resolvedor DNS iterativo simples, escrito em C. O programa é capaz de resolver nomes de domínio para endereços IPv4 começando a consulta a partir dos servidores raiz da internet e seguindo as delegações.

[cite_start]Este README contém as instruções para compilação e execução do programa.

## Pré-requisitos

Para compilar e executar este projeto, você precisará de:
* Um compilador C (como o `gcc`)
* A ferramenta `make`

## Compilação

O projeto utiliza um `Makefile` para simplificar o processo de compilação.

1.  Clone ou baixe o repositório e navegue até a pasta raiz do projeto.
2.  Execute o comando `make` no terminal:

    ```bash
    make
    ```
3.  Isso irá compilar todos os arquivos fonte da pasta `src/` e criar um executável chamado `dns_resolver` na pasta raiz.

Para limpar os arquivos compilados, você pode usar o comando:
```bash
make clean
