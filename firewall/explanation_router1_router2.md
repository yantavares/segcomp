## Análise do Tráfego Final da Rede (Wireshark)

Esta análise corresponde à captura de pacotes no link entre o `Router1` e o `Router2`, após a `Workstation` ter obtido seu endereço IP via DHCP.

### O Cenário do Teste

- A `Workstation`, agora com um endereço IP válido (ex: `10.0.40.103`), começa a operar normalmente.
- Como parte de sua inicialização normal, o sistema Ubuntu tenta se comunicar com a internet externa para serviços como sincronização de tempo (`ntp.ubuntu.com`), o que requer uma consulta ao servidor DNS (`8.8.8.8`) que foi fornecido via DHCP.
- A captura de pacotes nos permite observar como a nossa rede projetada lida com esse tráfego destinado ao mundo exterior.

### A Jornada do Pacote (O que Vemos na Captura)

A sequência de pacotes na captura conta uma história clara e correta:

1.  **Tentativa de Conexão:** A `Workstation` (`10.0.40.103`) envia pacotes (DNS e TCP) destinados a um IP na internet, o `8.8.8.8`.

2.  **Roteamento Interno:** Esses pacotes são corretamente encaminhados pelo seu gateway (`Router2`) e chegam ao `Router1`. Vemos isso nos pacotes `DHCP Discover` (na verdade, pacotes DNS e TCP, como mostra a imagem `image_fc0dbf.png`) que têm como origem o IP do `Router2` (atuando como gateway) ou diretamente da `Workstation` e atravessam o link.

3.  **A Barreira na Borda:** O `Router1` é o nosso roteador de borda. Ele recebe os pacotes destinados ao `8.8.8.8`, consulta sua tabela de roteamento e percebe que **não possui** uma rota para a internet externa. A única rota estática que ele conhece é para a rede interna `10.0.40.0/24`.

4.  **A Resposta Correta do Roteador:** Ao determinar que o destino é inalcançável, o `Router1` cumpre seu papel e envia uma mensagem de erro **ICMP** de volta para a `Workstation`, informando: `Destination unreachable (Network unreachable)`.
