### Como Funciona

**Fórmula de Cifração:**

```
Ci = (Pi + Ki) mod 26
```

- `Ci` = letra cifrada
- `Pi` = letra original (plaintext)
- `Ki` = letra da chave
- `mod 26` = operação módulo (volta ao início do alfabeto)

## FUNDAMENTOS MATEMÁTICOS

### Índice de Coincidência (IC)

**O que é:**
Probabilidade de duas letras escolhidas aleatoriamente serem iguais.

**Fórmula:**

```
IC = Σ(fi × (fi - 1)) / (N × (N - 1))
```

- `fi` = frequência de cada letra
- `N` = total de letras

**Valores Típicos:**

- **Português**: ~0.0761 (texto natural)
- **Inglês**: ~0.0667
- **Texto aleatório**: ~0.0385 (1/26)
- **Caesar/substituição simples**: ~0.065-0.075

**Por que funciona:**

- Línguas naturais têm distribuição não-uniforme de letras
- Cifras polialfabéticas "espalham" essa distribuição
- IC baixo indica cifra polialfabética

### Determinação do Tamanho da Chave

**Método do IC (implementado):**

1. Dividir texto em subsequências (espaçamento = tamanho da chave testado)
2. Calcular IC médio das subsequências
3. Tamanho correto → IC próximo ao natural do idioma

**Por que funciona:**

- Se o tamanho estiver correto, cada subsequência foi cifrada com a mesma letra
- Isso restaura parcialmente a distribuição natural
- IC das subsequências aumenta

### Recuperação da Chave Individual

**Após determinar o tamanho:**

1. Extrair subsequências (uma para cada posição da chave)
2. Para cada subsequência, testar todos os 26 possíveis deslocamentos
3. Usar análise estatística para determinar o melhor

**Dois Métodos Implementados:**

**Método 1 - Qui-Quadrado:**

```
χ² = Σ((Observado - Esperado)² / Esperado)
```

- Compara frequências observadas vs. esperadas para o idioma
- Menor χ² = melhor ajuste

**Método 2 - Correlação Simples:**

```
Correlação = Σ(freq_observada × freq_esperada)
```

- Maior correlação = melhor ajuste
- Mais simples, funciona bem para textos curtos
