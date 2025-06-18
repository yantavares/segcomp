# Assinatura Digital RSA - Implementação Completa

## Descrição

Este projeto contém uma implementação completa de assinatura digital usando o algoritmo RSA, incluindo funcionalidades para geração de chaves, assinatura de arquivos e verificação de assinaturas.

O RSA (Rivest-Shamir-Adleman) é um dos algoritmos de criptografia assimétrica mais utilizados. Nesta implementação, utilizamos RSA com padding OAEP (Optimal Asymmetric Encryption Padding) e hash SHA3-256 para garantir a segurança das assinaturas.

## Funcionalidades

O programa oferece três funcionalidades principais:

1. **Geração de chaves RSA**: Gera um par de chaves (pública e privada) de 2048 bits
2. **Assinatura de arquivos**: Permite assinar um arquivo usando a chave privada
3. **Verificação de assinaturas**: Permite verificar a autenticidade de um arquivo assinado usando a chave pública

## Detalhes Técnicos

### Geração de Chaves

- Tamanho das chaves: 2048 bits
- Geração de números primos usando o teste de primalidade de Miller-Rabin
- Expoente público fixo em 65537 (0x10001)
- Chaves são salvas em arquivos separados (public_key.txt e private_key.txt)

### Assinatura Digital

O processo de assinatura segue estes passos:

1. Cálculo do hash SHA3-256 do arquivo
2. Aplicação do padding OAEP ao hash
3. "Cifração" do hash com padding usando a chave privada
4. Codificação Base64 do resultado

### Verificação de Assinatura

O processo de verificação segue estes passos:

1. Decodificação Base64 da assinatura
2. "Decifração" da assinatura usando a chave pública
3. Remoção do padding OAEP
4. Cálculo do hash SHA3-256 do arquivo original
5. Comparação dos hashes

## Compilação e Uso

### Requisitos

- Compilador C (GCC recomendado)
- Biblioteca GMP (GNU Multiple Precision Arithmetic Library)
- Biblioteca OpenSSL
- Biblioteca Standard C

### Compilação

```bash
gcc -o rsa_signer main.c -lgmp -lssl -lcrypto
```

### Uso

Execute o programa:

```bash
./rsa_signer
```

Siga as instruções no menu interativo para:

1. Gerar um par de chaves RSA
2. Assinar um arquivo
3. Verificar uma assinatura

## Exemplo de Uso

### Gerando um par de chaves

```
===== ASSINATURA DIGITAL RSA - MENU PRINCIPAL =====
1. Gerar chaves RSA
2. Assinar arquivo
3. Verificar assinatura
0. Sair
Escolha uma opção: 1

Gerando par de chaves RSA de 2048 bits...
Gerando primo p de 1024 bits... OK
Gerando primo q de 1024 bits... OK
Chaves salvas em 'public_key.txt' e 'private_key.txt'.
```

### Assinando um arquivo

```
===== ASSINATURA DIGITAL RSA - MENU PRINCIPAL =====
1. Gerar chaves RSA
2. Assinar arquivo
3. Verificar assinatura
0. Sair
Escolha uma opção: 2

Digite o nome do arquivo a ser assinado: meu_arquivo.txt
Digite o nome do arquivo da chave privada (ex: private_key.txt): private_key.txt
Arquivo assinado com sucesso e salvo como 'meu_arquivo.txt.signed'.
```

### Verificando uma assinatura

```
===== ASSINATURA DIGITAL RSA - MENU PRINCIPAL =====
1. Gerar chaves RSA
2. Assinar arquivo
3. Verificar assinatura
0. Sair
Escolha uma opção: 3

Digite o nome do arquivo assinado (ex: arquivo.txt.signed): meu_arquivo.txt.signed
Digite o nome do arquivo da chave pública (ex: public_key.txt): public_key.txt

=========================
ASSINATURA VÁLIDA!
=========================
```

## Formato dos Arquivos

### Arquivo de Chave Pública
```
<n em hexadecimal>
<e em hexadecimal>
```

### Arquivo de Chave Privada
```
<n em hexadecimal>
<d em hexadecimal>
```

### Arquivo Assinado
```
-----BEGIN SIGNED MESSAGE-----
<conteúdo do arquivo em Base64>
-----BEGIN SIGNATURE-----
<assinatura em Base64>
-----END SIGNATURE-----
```

## Limitações

- O tamanho máximo do arquivo que pode ser assinado é limitado pelo tamanho da chave RSA (2048 bits)
- A geração de chaves pode levar alguns segundos devido ao processo de geração de números primos
- O programa não implementa revogação de chaves ou certificados digitais

## Documentação

O projeto inclui comentários detalhados no código-fonte para explicar a lógica de cada parte da implementação. A documentação pode ser compilada usando Doxygen, se desejado.

```bash
doxygen Doxyfile
```

Para visualizar a documentação gerada, abra o arquivo `index.html` na pasta `html/`.

## Autores

Yan Tavares - 202014323

Eduardo Marques - 211021004 