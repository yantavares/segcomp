### Como Funciona

**Fórmula de Assinatura:**

```
S = (H^d) mod n
```

- `S` = assinatura
- `H` = hash da mensagem
- `d` = chave privada
- `n` = módulo RSA

## FUNDAMENTOS MATEMÁTICOS

### Geração de Chaves RSA

**O que é:**
Processo de geração de um par de chaves (pública e privada) usando números primos grandes.

**Passos:**

1. Gerar dois números primos grandes (p e q)
2. Calcular n = p × q
3. Calcular φ(n) = (p-1) × (q-1)
4. Escolher e (expoente público) = 65537
5. Calcular d (expoente privado) = e^(-1) mod φ(n)

**Por que funciona:**
- Fatoração de n em p e q é computacionalmente difícil
- Conhecendo p e q, é fácil calcular d
- Sem p e q, é difícil calcular d a partir de e e n

### Padding OAEP

**O que é:**
Optimal Asymmetric Encryption Padding - esquema de padding que adiciona aleatoriedade e redundância.

**Passos:**

1. Gerar seed aleatória
2. Aplicar MGF1 (Mask Generation Function) à seed
3. XOR com a mensagem
4. Aplicar MGF1 ao resultado
5. XOR com a seed

**Por que funciona:**
- Adiciona aleatoriedade para evitar ataques determinísticos
- Inclui redundância para detectar manipulação
- Torna o padding resistente a ataques de padding oracle

### Função de Hash SHA3-256

**O que é:**
Função de hash criptográfica que produz uma saída de 256 bits.

**Características:**
- Resistente a colisões
- Resistente a pré-imagem
- Resistente a segunda pré-imagem
- Baseada na família Keccak

**Por que funciona:**
- Transforma qualquer entrada em uma saída de tamanho fixo
- Pequenas mudanças na entrada causam grandes mudanças na saída
- É computacionalmente inviável encontrar duas entradas com o mesmo hash

### Verificação de Assinatura

**Fórmula:**

```
H' = (S^e) mod n
```

- `H'` = hash recuperado
- `S` = assinatura
- `e` = chave pública
- `n` = módulo RSA

**Processo:**
1. Recuperar o hash usando a chave pública
2. Calcular o hash da mensagem original
3. Comparar os dois hashes

**Por que funciona:**
- Apenas quem conhece d pode gerar uma assinatura válida
- Qualquer alteração na mensagem muda o hash
- A verificação usa apenas a chave pública

### Observações Finais

- Complexidade do algoritmo: O(log n) para operações modulares
- Segurança baseada na dificuldade de fatoração
- Tamanho da chave: 2048 bits (recomendado atualmente)
- Como melhorar?
  - Implementar certificados digitais
  - Adicionar revogação de chaves
  - Usar curvas elípticas para maior eficiência 