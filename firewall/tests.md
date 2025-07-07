# Plano de Testes Finais - Projeto Firewall

O objetivo destes testes é validar que o firewall está funcionando conforme as regras definidas: permitindo o tráfego necessário e bloqueando todo o resto.

---

## Teste 1: Acesso HTTP Permitido da Internet para a DMZ (Deve Funcionar)

- **Objetivo:** Validar a regra do firewall que permite acesso web ao WebServer.
- **Máquina de Origem:** `WebTermPublic`
- **Comando a Executar:**
  ```bash
  curl http://10.0.20.1
  ```
- **Resultado Esperado:** **SUCESSO**.
- **Verificação:** O comando deve retornar o conteúdo HTML da página de teste (ex: `<h1>Firewall Test Page - OK</h1>`). Isso prova que a Regra 2 do firewall (permitir TCP porta 80) está funcionando.

---

## Teste 2: Bloqueio de Outros Protocolos (Ping) à DMZ (Deve Falhar)

- **Objetivo:** Provar que o firewall bloqueia tráfego não permitido (ex: ICMP/ping) para a DMZ, mesmo que a rede seja alcançável.
- **Máquina de Origem:** `WebTermPublic`
- **Comando a Executar:**
  ```bash
  ping 10.0.20.1
  ```
- **Resultado Esperado:** **FALHA**.
- **Verificação:** O comando `ping` não deve receber respostas, ficando "travado" até ser cancelado com `Ctrl+C`. Isso prova que a política padrão `DROP` do firewall está funcionando corretamente.

---

## Teste 3: Bloqueio de Acesso da Internet à Rede Interna (Deve Falhar)

- **Objetivo:** Provar que o firewall protege a rede interna de servidores contra acessos diretos da internet.
- **Máquina de Origem:** `WebTermPublic`
- **Comando a Executar:**
  ```bash
  ping 10.0.30.1
  ```
- **Resultado Esperado:** **FALHA**.
- **Verificação:** O comando `ping` não deve receber respostas. Isso prova que o firewall está protegendo a rede interna.

---

## Teste 4: Validação Final da Cadeia DHCP (Deve Funcionar)

- **Objetivo:** Provar que a cadeia DHCP (Servidor, Relay e as regras de firewall para DHCP) está funcionando corretamente.
- **Máquina de Origem:** `WebTermWorkstation`
- **Comando a Executar:**
  ```bash
  sudo dhclient -v enp0s3
  ```
- **Resultado Esperado:** **SUCESSO**.
- **Verificação:** A `Workstation` deve receber um endereço IP na faixa `10.0.40.100-150`, provando que as Regras 3 e 4 do firewall (permitir UDP portas 67) estão funcionando.
