# SEGCOMP - 2025/2

```

  _________             _________
 /   _____/ ____   ____ \_   ___ \  ____   _____ ______
 \_____  \_/ __ \ / ___\/    \  \/ /  _ \ /     \\____ \
 /        \  ___// /_/  >     \___(  <_> )  Y Y  \  |_> >
/_______  /\___  >___  / \______  /\____/|__|_|  /   __/
        \/     \/_____/         \/             \/|__|

```

Repositório para abrigar os códigos da disciplina de Segurança Computacional (SEGCOMP) da UnB. Mais detalhes sobre cada trabalho estão disponíveis nos diretórios correspondentes.

## Trabalho 1: [Cifra de Vigenère](./vigenere/)

Este projeto contém uma implementação completa da Cifra de Vigenère, incluindo:

- **Cifrar e Decifrar Mensagens**: funções para criptografar e descriptografar texto usando uma chave de repetição.
- **Módulo de Ataque**: recuperação da chave por meio de análise de frequência e ataque de força bruta.

## Trabalho 2: [Assinatura Digital RSA](./rsa/)

Este projeto fornece uma ferramenta web para Assinatura Digital baseada em RSA, com as seguintes funcionalidades:

- **Gerar Par de Chaves RSA**

  - Geração de chaves de 2048 bits (primos de 1024 bits) usando teste de primalidade Miller-Rabin.
  - Saída dos componentes `n`, `e` e `d` em hexadecimal.
  - Opção de download das chaves pública e privada.

- **Assinar Arquivo**

  - Seleção de qualquer arquivo para assinatura.
  - Cálculo do hash SHA3-256 do conteúdo, padding OAEP simplificado e cifragem com a chave privada (RSA-sign).
  - Geração de um arquivo `.signed` contendo o conteúdo codificado em Base64 e a assinatura.

- **Verificar Assinatura**

  - Upload de arquivo `.signed` e chave pública (formato: `n,e` em hexadecimal).
  - RSA-verify (cifrar a assinatura com `e, n`), unpad OAEP e comparação do hash recuperado com o hash recalculado.
  - Exibição de status de validade ou invalidade da assinatura.

- **Extrair Mensagem**

  - Decodificação do bloco de mensagem do arquivo `.signed` e exibição direta na interface.
  - Evita downloads adicionais, mostrando o conteúdo original em texto ou indicando quando é binário.

---

_Desenvolvido por Yan Tavares e Eduardo Marques_
