# NetProbe Wi-Fi

Ferramenta de inventário para redes domésticas. Descobre quais dispositivos estão conectados na rede, inclusive os que **bloqueiam ping**, mostra o **MAC** de cada um, as **portas abertas** e se ele está **online ou offline em tempo real**.

Trabalho final da disciplina de Redes de Computadores (Projeto 2).

---

## Como rodar

Precisa só do **Python 3** no **Windows**. Não precisa instalar nenhuma biblioteca nem ser administrador.

```powershell
python app.py
```

Teste rápido pelo terminal, sem janela:

```powershell
python scanner.py 192.168.15.0/24
```

## Arquivos

| Arquivo | O que tem |
|---|---|
| `scanner.py` | Toda a parte de **rede**: ping, ARP, MAC e portas. |
| `app.py` | A **janela** (Tkinter, que já vem com o Python). |

---

## Os 5 elementos avaliados

### 1. Varredura ICMP (Ping Sweep)
**Onde:** `fazer_ping()` e `varrer_rede()` em `scanner.py`.

- O programa manda **1 ping** (ICMP *Echo Request*) para cada IP da faixa `/24` (254 endereços). Quem está ligado responde com um *Echo Reply*.
- Usa o comando `ping` do Windows: `ping -n 1 -w <timeout> <ip>`. A resposta só conta como válida se tiver `TTL=`, porque o Windows também imprime "Host de destino inacessível" quando ninguém responde.
- **Agilidade:** os 254 IPs são testados **ao mesmo tempo** com 256 threads (`ThreadPoolExecutor`). Uma varredura completa leva ~10 s, contra mais de 30 minutos se fosse um IP por vez.
- **Parametrizável:** a **rede** (campo "Rede", ex.: `192.168.15.0/24`) e o **timeout do ping** (campo "Timeout do ping (ms)") são escolhidos na tela.

### 2. Mecanismo de sondagem ARP (para quem bloqueia ping)
**Onde:** `sondar_arp()` e `verificar_ip()` em `scanner.py`.

- Muitos aparelhos (ex.: Windows com firewall ativo) **ignoram ping**. Para cada IP que não respondeu, o programa manda um **ARP Request**: "quem tem o IP X? Me diga seu MAC".
- O ARP funciona na **camada 2** (enlace). Para usar a rede local, todo aparelho **precisa** responder ARP, mesmo bloqueando ping. Se a resposta chega, o IP está **ocupado**, só bloqueou o ICMP. Se não chega, o IP está **vazio** mesmo.
- É feito com a função `SendARP` do próprio Windows (`iphlpapi.dll`), chamada pelo `ctypes`. Ela envia um ARP de verdade, sem precisar de administrador nem de instalar nada.
- Na tela, esses aparelhos aparecem em **amarelo**, com "ARP (bloqueia ping)".

### 3. Vinculação IP/MAC
**Onde:** `verificar_ip()`, `sondar_arp()`, `mac_da_tabela_arp()` e `mac_deste_pc()` em `scanner.py`.

- A resposta ARP traz o **MAC** do aparelho. Ele é guardado junto com o IP num objeto `Host`, e esses pares formam a tabela.
- Quem respondeu ao ping também passa pelo ARP, para descobrir o MAC.
- Se o ARP falhar, há um plano B: ler a **tabela ARP do Windows** (`arp -a`).
- O MAC do próprio PC sai do `ipconfig /all`, porque um computador não manda ARP para si mesmo.

### 4. Interface do usuário (status em tempo real)
**Onde:** `app.py`.

- Tabela com **IP, MAC, Status, Descoberto por, Tempo de resposta, Portas abertas e Visto por último**.
- Cores: **verde** = online (respondeu ao ping), **amarelo** = online (achado por ARP), **vermelho** = offline.
- A tabela se preenche **enquanto** a varredura acontece. A varredura roda numa thread separada e manda mensagens para a tela por uma fila (`queue.Queue`), para a janela nunca travar.
- **Monitorar em tempo real:** repete a varredura a cada N segundos. Um aparelho que estava na rede e sumiu vira **OFFLINE** depois de faltar em 2 rodadas seguidas. A tolerância existe porque celulares em economia de energia às vezes deixam de responder uma vez.

### 5. Portas abertas
**Onde:** `porta_aberta()` e `escanear_portas()` em `scanner.py`.

- Para cada IP **online**, tenta abrir uma conexão **TCP** em cada porta do intervalo escolhido. Isso dispara o *three-way handshake*: SYN → SYN-ACK → ACK.
- Se conecta (`connect_ex` devolve 0), há um programa escutando: a porta está **aberta**. Se o aparelho responde RST ou não responde até o timeout, a porta está fechada ou filtrada.
- **Parametrizável:** porta **inicial**, porta **final** e **timeout** de cada porta.
- 200 portas são testadas ao mesmo tempo. Portas conhecidas aparecem com o nome do serviço, ex.: `80 (HTTP)`, `22 (SSH)`, `445 (SMB)`.

---

## Fluxo de uma varredura

```
para cada IP da rede (todos ao mesmo tempo):
    respondeu ao PING?
        sim -> ONLINE (verde)   + ARP para descobrir o MAC
        não -> manda ARP
                 respondeu? sim -> ONLINE, bloqueia ping (amarelo)
                            não -> IP vazio (não aparece)
depois, para cada IP online:
    testa as portas TCP do intervalo -> lista as abertas
modo monitorar:
    espera N segundos e repete; quem faltar 2 vezes -> OFFLINE (vermelho)
```

---

## Roteiro para a apresentação

**Use o hotspot do celular**, não o Wi-Fi da faculdade. Redes de faculdade costumam isolar os aparelhos uns dos outros ("client isolation"), e nada seria encontrado.

1. Ligue o hotspot do celular A e conecte nele o **notebook que roda o NetProbe** e mais **dois aparelhos**:
   - um que **responde ping** (ex.: outro celular);
   - um que **bloqueia ping** (ex.: um notebook Windows, que já bloqueia ping por padrão em rede "Pública").
2. Antes da apresentação, confira o aparelho que bloqueia ping. Neste comando, a resposta precisa ser "Esgotado o tempo limite":
   ```powershell
   ping <ip-dele>
   ```
3. Rode `python app.py`, confira se a rede sugerida é a do hotspot e clique em **Iniciar varredura**.
4. Mostre: o verde (ping), o **amarelo** (achado só por ARP), os MACs e as portas abertas.
5. Marque **Monitorar em tempo real** (ex.: a cada 10 s) e **desligue o Wi-Fi de um aparelho**. Depois de duas rodadas, ele fica vermelho (OFFLINE). Religue e ele volta a ficar verde.
6. Mude o **timeout do ping** e o **intervalo de portas** para mostrar que são parametrizáveis.

> Para um aparelho Windows **responder** ping (ou deixar de responder), a regra fica em: Firewall do Windows → Configurações avançadas → Regras de entrada → "Compartilhamento de Arquivo e Impressora (Solicitação de Eco - ICMPv4-In)".

---

## Limitações conhecidas

- Feito para **Windows**: usa o `ping` do Windows e a função `SendARP`.
- O ARP só funciona na **mesma rede local**. Não dá para descobrir MAC de aparelhos em outra rede, porque o ARP não passa pelo roteador.
- Um aparelho que acabou de sair pode continuar aparecendo por alguns segundos, porque o Windows guarda os MACs num cache ARP.
- A varredura de portas é do tipo *TCP connect*. Ela não testa portas **UDP**.
