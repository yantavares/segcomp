# Cifra de Vigenère - Implementação e Ataque de Análise de Frequência

## Descrição

Este projeto contém uma implementação completa da cifra de Vigenère, incluindo funcionalidades para cifrar e decifrar mensagens, além de um módulo de ataque para recuperação de senha através de análise de frequência.

A cifra de Vigenère é uma técnica de criptografia polialfabética que utiliza uma série de cifras de César diferentes para cifrar uma mensagem. O uso de múltiplos alfabetos cifrados baseados em uma palavra-chave dificulta significativamente a análise de frequência tradicional, tornando esta cifra historicamente mais resistente que as cifras monoalfabéticas.

## Funcionalidades

O programa oferece três funcionalidades principais:

1. **Cifragem de mensagem**: Permite cifrar um texto usando uma chave fornecida pelo usuário
2. **Decifragem de mensagem**: Permite decifrar um texto cifrado usando a chave correspondente
3. **Ataque de recuperação de senha**: Implementa técnicas criptanalíticas para descobrir a chave e decifrar a mensagem sem conhecimento prévio da chave

## Teoria da Criptoanálise

### Índice de Coincidência (IC)

O módulo de ataque utiliza o Índice de Coincidência (IC) como ferramenta principal para determinar o tamanho da chave. O IC mede a probabilidade de duas letras selecionadas aleatoriamente em um texto serem iguais.

Para um texto em português, o IC esperado é aproximadamente 0,072.  
Para um texto em inglês, o IC esperado é aproximadamente 0,067.  
Para um texto com distribuição aleatória uniforme, o IC esperado é 0,038 (1/26).

Em uma cifra de Vigenère, ao separar o texto em subsequências correspondentes a cada posição da chave, espera-se que cada subsequência tenha um IC próximo ao do idioma original, já que cada uma foi cifrada com a mesma letra da chave.

### Processo de Ataque

O ataque implementado segue estes passos:

1. **Determinação do tamanho da chave**:

   - Testa diferentes tamanhos de chave (1 a 20 por padrão)
   - Para cada tamanho, divide o texto em subsequências correspondentes
   - Calcula o IC médio das subsequências
   - O tamanho que produz subsequências com IC mais próximo do idioma original é provavelmente o correto

2. **Recuperação da chave**:
   - Para cada posição da chave, extrai a subsequência correspondente
   - Testa os 26 possíveis deslocamentos para aquela posição
   - Usa correlação entre as frequências observadas e as esperadas para o idioma
   - Identifica o deslocamento mais provável para cada posição da chave

## Compilação e Uso

### Requisitos

- Compilador C (GCC recomendado)
- Biblioteca Standard C

### Compilação

```bash
gcc -o vigenere main.c -lm
```

### Uso

Execute o programa:

```bash
./vigenere
```

Siga as instruções no menu interativo para:

1. Cifrar uma mensagem
2. Decifrar uma mensagem
3. Realizar ataque de recuperação de senha

## Exemplo de Uso

### Cifrando uma mensagem

```
===== CIFRA DE VIGENÈRE =====
1. Cifrar mensagem
2. Decifrar mensagem
3. Realizar ataque de recuperação de senha
0. Sair
Escolha uma opção: 1

===== CIFRAR MENSAGEM =====
Escolha uma opção:
1. Digitar o texto a ser cifrado
2. Carregar o texto de um arquivo
Opção: 1
Digite o texto a ser cifrado:
A literatura brasileira é rica em diversidade e história.
Digite a chave: literatura

Texto cifrado:
L WVFLRDGVCL FNLJIWPMRL É IKPL XY QIOLKZUHLHL M UBDFÓIPL.
```

### Realizando ataque de recuperação de senha

```
===== CIFRA DE VIGENÈRE =====
1. Cifrar mensagem
2. Decifrar mensagem
3. Realizar ataque de recuperação de senha
0. Sair
Escolha uma opção: 3

===== ATAQUE DE RECUPERAÇÃO DE SENHA =====
Escolha uma opção:
1. Digitar o texto cifrado
2. Carregar o texto cifrado de um arquivo
Opção: 1
Digite o texto cifrado:
L WVFLRDGVCL FNLJIWPMRL É IKPL XY QIOLKZUHLHL M UBDFÓIPL.

Selecione o idioma do texto original:
1. Português
2. Inglês
Opção: 1

Analisando o texto cifrado...

Tamanho de chave mais provável: 10
Chave recuperada: literatura

Texto decifrado:
A literatura brasileira é rica em diversidade e história.
```

Arquivos para teste estão disponíveis na pasta `arquivos/`. Eles contêm textos que demonstram aspectos importantes da cifra de Vigenère:

- `ptbr.txt`: Texto em português. O ataque funciona corretamente para a chave "literatura" automaticamente.

- `ptbr2.txt`: Texto em português. O ataque funciona corretamente para a chave "teste", mas, por ser um texto pequeno, o resultado funciona se o tamanho da chave for fornecido.

- `en.txt`: Texto em inglês. O ataque funciona corretamente para a chave "literatura" automaticamente.

Importante ressaltar que, embora as chaves testadas sejam "literatura" e "teste", o ataque pode ser aplicado a qualquer texto cifrado, independentemente da chave utilizada.

## Limitações

- O ataque funciona melhor com textos longos (recomendado mais de 100 caracteres)
- A eficácia do ataque depende da qualidade da distribuição de frequência do texto original
- Textos muito curtos ou com distribuições incomuns podem não ser decifrados corretamente
- O tamanho máximo da chave para tentativa de recuperação é limitado a 20 por padrão

## Autores

Yan Tavares - 202014323
Eduardo Marques - 211021004
