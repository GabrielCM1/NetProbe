# NetProbe Wi-Fi

**Monitoramento de rede doméstica por Ping Scan, sondagem ARP e detecção de colisão de IP.**

O NetProbe descobre quais dispositivos estão conectados na rede local, **inclusive os que bloqueiam ping**. Para cada um, ele mostra o MAC, as portas TCP abertas e se o aparelho está online ou offline, atualizando tudo em tempo real. Também avisa quando dois aparelhos disputam o mesmo IP.

Trabalho final da disciplina de **Redes de Computadores**, Projeto 2.

| Elemento avaliado | Como o NetProbe resolve | Onde está no código |
|---|---|---|
| Varredura ICMP (Ping Sweep) | 254 pings em paralelo, com a rede e o timeout escolhidos na tela | `fazer_ping()`, `varrer_rede()` |
| Mecanismo de colisão / ARP Probe | ARP Request para todo IP que não respondeu ao ping | `sondar_arp()`, `verificar_ip()` |
| Vinculação IP/MAC | Tabela IP ↔ MAC, com alerta de colisão de IP | `verificar_ip()`, `mac_da_tabela_arp()`, `_mac_mudou()` |
| Interface do usuário | Tabela colorida que se atualiza durante a varredura, com modo monitorar | `app.py` |
| Portas abertas | *TCP connect scan* no intervalo de portas escolhido | `escanear_portas()` |

---

## Sumário

1. [Requisitos e instalação](#1-requisitos-e-instalação)
2. [Como usar](#2-como-usar)
3. [Como funciona](#3-como-funciona)
4. [Colisão de IP](#4-colisão-de-ip)
5. [Desempenho](#5-desempenho)
6. [Testes automatizados](#6-testes-automatizados)
7. [Estrutura do código](#7-estrutura-do-código)
8. [Roteiro para a apresentação](#8-roteiro-para-a-apresentação)
9. [Limitações conhecidas](#9-limitações-conhecidas)
10. [Uso responsável](#10-uso-responsável)

---

## 1. Requisitos e instalação

- **Python 3.9 ou mais novo**
- **Windows** ou **Linux**
- **Nenhuma biblioteca externa.** Só a biblioteca padrão do Python é usada (`socket`, `subprocess`, `ctypes`, `tkinter`, `threading`).
- **Não precisa de administrador nem de root.**

Para baixar o projeto:

```bash
git clone https://github.com/GabrielCM1/NetProbe.git
cd NetProbe
```

**Windows:** o Tkinter já vem com o instalador oficial do Python. Não precisa de mais nada.

**Linux:** algumas distribuições separam o Tkinter num pacote próprio. Se `python3 app.py` reclamar de `tkinter`, instale:

```bash
sudo dnf install python3-tkinter      # Fedora
sudo apt install python3-tk           # Ubuntu / Debian
```

> Nos exemplos abaixo, use `python` no Windows e `python3` no Linux.

---

## 2. Como usar

### 2.1. Interface gráfica

```bash
python app.py
```

**Campos de configuração**

| Campo | O que faz | Padrão |
|---|---|---|
| Rede | Faixa de IPs a varrer. Aceita `192.168.0.0/24` ou só `192.168.0.0`, que vira /24. Já vem preenchido com a rede deste PC. | rede local |
| Timeout do ping (ms) | Quanto tempo esperar a resposta de cada ping (100 a 5000) | 500 |
| Portas de / até | Intervalo de portas TCP testadas em cada aparelho online (1 a 65535) | 1 a 1024 |
| Timeout da porta (ms) | Quanto tempo esperar em cada porta (50 a 5000) | 300 |
| Monitorar em tempo real | Repete a varredura sozinho a cada N segundos (5 a 600) | desligado, 20 s |

**Botões**

- **Iniciar varredura:** começa a varredura. A tabela vai se preenchendo enquanto ela acontece.
- **Parar:** interrompe a varredura em andamento ou cancela a próxima rodada do monitoramento.
- **Limpar tabela:** apaga a tabela e o histórico de rodadas.
- **Exportar CSV:** salva o inventário num arquivo `.csv`, separado por `;` e em UTF-8. Abre direto no Excel em português, com os acentos certos.

**Colunas da tabela**

| Coluna | Conteúdo |
|---|---|
| IP | Endereço IPv4 do aparelho |
| MAC | Endereço físico, no formato `AA-BB-CC-DD-EE-FF` |
| Status | Online ou Offline |
| Descoberto por | `Ping (ICMP)`, `ARP (bloqueia ping)` ou `Este computador` |
| Resposta | Tempo de resposta do ping |
| Portas abertas | Portas TCP abertas no intervalo, com o nome do serviço, ex.: `80 (HTTP)` |
| Visto por último | Horário em que o aparelho respondeu pela última vez |
| Observações | Avisos: colisão de IP, MAC repetido, MAC aleatório |

**Cores**

| Cor | Significado |
|---|---|
| 🟩 Verde | Online: respondeu ao ping |
| 🟨 Amarelo | Online: **bloqueia ping**, foi encontrado pelo ARP |
| 🟥 Vermelho | Offline: estava na rede e sumiu |
| 🟧 Laranja | **Colisão de IP**: o MAC deste IP mudou |

Embaixo da tabela, o **Registro** mostra cada evento com horário: aparelho novo, aparelho que saiu, portas encontradas e alertas.

### 2.2. Pelo terminal, sem janela

```bash
python scanner.py [rede] [timeout_ms]
```

```bash
python scanner.py                      # rede deste PC, timeout de 500 ms
python scanner.py 192.168.1.0/24 300   # rede e timeout escolhidos
```

Saída de exemplo (os MACs foram trocados):

```
Varrendo 192.168.1.0/24 (timeout 500 ms)...
Pronto em 6.8 s. 7 dispositivo(s):
  192.168.1.1     F4-E8-4F-00-00-01 PING   2 ms  portas: 53 (DNS), 80 (HTTP), 443 (HTTPS)
  192.168.1.4     A8-E6-21-00-00-02 ARP       -  portas: nenhuma
  192.168.1.18    A8-16-D0-00-00-03 PING 153 ms  portas: nenhuma
  192.168.1.154   FE-CB-1F-00-00-04 PING  <1 ms  portas: nenhuma (este PC)
```

O aparelho `192.168.1.4` aparece com `ARP`: ele ignorou o ping, mas foi encontrado mesmo assim. No modo terminal, as portas testadas são sempre de 1 a 1024, com timeout de 300 ms.

---

## 3. Como funciona

### Fluxo de uma varredura

```
para cada IP da rede (todos ao mesmo tempo):
    é o IP deste PC?  -> ONLINE, MAC lido do sistema
    respondeu ao PING?
        sim -> ONLINE (verde), MAC lido do cache ARP
        não -> manda ARP Request
                 respondeu? sim -> ONLINE, bloqueia ping (amarelo)
                            não -> IP vazio (não aparece)

depois, para cada IP online (3 aparelhos por vez):
    testa as portas TCP do intervalo -> lista as abertas

modo monitorar (a cada N segundos, repete tudo):
    faltou em 2 rodadas seguidas      -> OFFLINE (vermelho)
    voltou                            -> ONLINE de novo, portas verificadas de novo
    IP online respondeu com outro MAC -> COLISÃO DE IP (laranja)
```

### 3.1. Varredura ICMP (Ping Sweep)

O programa manda **um ICMP Echo Request** para cada IP da faixa. Quem está ligado devolve um **Echo Reply**.

| Sistema | Comando usado |
|---|---|
| Windows | `ping -n 1 -w <timeout_ms> <ip>` |
| Linux | `ping -c 1 -n -W <timeout_s> <ip>` |

- **Precisão:** a resposta só conta se tiver `TTL=`. Quando ninguém responde, o próprio roteador ou o PC pode imprimir "Host de destino inacessível" ou "Destination Host Unreachable", mas essas mensagens não têm TTL. Sem essa conferência, IPs vazios apareceriam como online.
- **Saída sempre igual:** no Linux, o comando roda com `LC_ALL=C`, então o texto sai sempre em inglês, qualquer que seja o idioma do sistema. No Windows, a saída é lida na codificação do console (`cp850`), e o programa entende as versões em português e em inglês.
- **Agilidade:** os 254 IPs de uma /24 são testados **ao mesmo tempo**, com 256 threads (`ThreadPoolExecutor`).
- **Parametrizável:** a **rede** e o **timeout do ping** são escolhidos na tela. A rede pode ter até 1024 IPs (/22).

### 3.2. Sondagem ARP (para quem bloqueia ping)

Muitos aparelhos ignoram ping de propósito. O Windows, por exemplo, faz isso por padrão em redes "Públicas". O ping sozinho diria que o IP está vazio.

A saída é descer para a **camada 2**. O ARP (*Address Resolution Protocol*) pergunta para a rede inteira: *"quem tem o IP X? Me diga seu MAC"*. Para conseguir usar a rede local, todo aparelho **precisa** responder ao ARP, mesmo que o firewall bloqueie ICMP. Então, para cada IP que não respondeu ao ping:

- **chegou resposta ARP:** o IP está **ocupado** e o aparelho só bloqueia ping;
- **não chegou resposta:** o IP está **vazio** mesmo.

Cada IP recebe 2 tentativas, porque celulares em economia de energia às vezes demoram a responder.

**Windows:** usa a função `SendARP` da biblioteca do sistema `iphlpapi.dll`, chamada pelo `ctypes`. Ela manda o ARP Request de verdade e devolve o MAC, sem precisar de administrador.

**Linux:** montar um pacote ARP manualmente exige root (*raw socket*). O NetProbe contorna isso assim:

1. Manda um datagrama **UDP** qualquer para a porta 9 do IP.
2. Para entregar esse datagrama, o **kernel é obrigado a descobrir o MAC**, então ele mesmo envia o ARP Request: 3 tentativas, uma por segundo.
3. O programa acompanha o resultado na tabela de vizinhos do kernel (`ip -4 neigh`):
   - `REACHABLE`: o aparelho respondeu ao ARP, então existe.
   - `FAILED`: ninguém respondeu, então o IP está vazio.
   - nenhuma entrada: o IP está fora da rede local e não dá para usar ARP.

A tabela de vizinhos é lida no máximo a cada 0,25 s e compartilhada entre todas as threads. Assim, 254 threads não rodam 254 comandos ao mesmo tempo.

### 3.3. Vinculação IP/MAC

| Situação | De onde vem o MAC |
|---|---|
| Respondeu ao ARP | Da própria resposta ARP |
| Respondeu ao ping | Do cache ARP do sistema, porque o ping já fez o ARP antes de enviar. Se não estiver lá, uma nova sondagem ARP. |
| É este computador | Windows: `ipconfig /all`. Linux: `ip addr` + `/sys/class/net/<placa>/address`. Um PC não manda ARP para si mesmo. |

- Todos os MACs são **normalizados** para `AA-BB-CC-DD-EE-FF`. Os valores inválidos `00-00-00-00-00-00` e `FF-FF-FF-FF-FF-FF` são descartados.
- O par IP ↔ MAC fica guardado num objeto `Host`. Se o ARP falhar numa rodada, o MAC conhecido da rodada anterior é mantido.
- A tabela também detecta **colisões de IP**, explicadas na [seção 4](#4-colisão-de-ip).

### 3.4. Interface em tempo real

- A varredura roda numa **thread separada**, e a janela nunca trava. A thread não mexe na tela diretamente. Ela manda mensagens por uma fila (`queue.Queue`), e a janela lê essa fila a cada 100 ms. Esse é o jeito seguro de usar threads com Tkinter.
- **Modo monitorar:** repete a varredura a cada N segundos. Um aparelho só vira **OFFLINE** depois de faltar em **2 rodadas seguidas**. Celulares em economia de energia às vezes deixam de responder uma vez, e sem essa tolerância a tabela ficaria piscando.
- Quando um aparelho volta, ele fica verde de novo, e as portas dele são verificadas outra vez.

### 3.5. Portas abertas (TCP connect scan)

Para cada IP **online**, o programa tenta abrir uma conexão TCP em cada porta do intervalo. Isso dispara o *three-way handshake* (SYN → SYN-ACK → ACK):

| Resposta do aparelho | Resultado |
|---|---|
| SYN-ACK (conectou, `connect_ex` devolve 0) | Porta **aberta**: tem um programa escutando |
| RST | Porta fechada |
| Nada até o timeout | Porta filtrada por firewall (é tratada como fechada) |

- **Parametrizável:** porta **inicial**, porta **final** e **timeout** de cada porta.
- **Agilidade:** 200 portas por aparelho ao mesmo tempo, e 3 aparelhos em paralelo.
- As portas conhecidas aparecem com o nome do serviço: `22 (SSH)`, `80 (HTTP)`, `445 (SMB)`, `3389 (Área Remota)`, `62078 (iPhone-sync)` etc.

---

## 4. Colisão de IP

Colisão de IP é quando **dois aparelhos usam o mesmo endereço IP**. Normalmente acontece com IP fixo configurado repetido. Também pode ser sinal de **ARP spoofing**: um atacante responde ao ARP no lugar de outro aparelho para interceptar o tráfego.

O NetProbe compara o MAC de cada IP de uma rodada para a outra:

| O que aconteceu | Como aparece |
|---|---|
| IP **online** respondeu com **outro MAC** | 🟧 **Alerta de colisão de IP.** A linha fica laranja, a coluna Observações mostra o MAC antigo, e o resumo conta as colisões. |
| IP **offline** voltou com outro MAC | Não é colisão: o roteador (DHCP) entregou o IP para outro aparelho. Fica só registrado no log. |
| **Mesmo MAC** em vários IPs | Observação "mesmo MAC que …". Pode ser um repetidor Wi-Fi, um aparelho com dois IPs ou ARP spoofing contra o roteador. |
| MAC com o bit "administrado localmente" ligado | Observação "MAC aleatório (privacidade)". Android, iPhone e Windows inventam um MAC por rede. |

Quando o MAC de um IP muda, as portas daquele IP são verificadas de novo, porque agora é outro aparelho.

---

## 5. Desempenho

Medido num notebook com Linux (Fedora) e Wi-Fi doméstico, rede /24 com 7 aparelhos:

| Operação | Tempo |
|---|---|
| Varredura completa da /24 (ping + ARP) | **~7 s** |
| Mesma varredura, um IP por vez (estimativa) | mais de 25 min |
| Portas 1 a 1024 do roteador (timeout de 300 ms) | ~0,3 s |
| Resposta do botão **Parar** | ~0,25 s |

O tempo total depende principalmente dos IPs **vazios**. Cada um espera as duas tentativas de ARP, cerca de 3 s cada, e todos esperam ao mesmo tempo.

---

## 6. Testes automatizados

São 32 testes com `unittest`, da biblioteca padrão. Eles **não precisam de rede**:

```bash
python -m unittest discover -s tests -v
```

| Arquivo | O que verifica |
|---|---|
| `tests/test_scanner.py` | Interpretação de saídas **reais** do `ping` (Windows em PT e EN, Linux) e da tabela ARP (`arp -a` e `ip neigh`), incluindo os casos de "host inacessível" sem TTL. Normalização de MAC e detecção de MAC aleatório. Validação do campo Rede. A lógica *ping → ARP → IP vazio*. Varredura de portas contra um **servidor TCP de verdade** em `127.0.0.1`. |
| `tests/test_app.py` | A interface, simulando rodadas: cores de ping e ARP, OFFLINE só depois de 2 faltas, aparelho que volta, **colisão de IP**, IP reaproveitado pelo DHCP (que não é colisão), MAC repetido, MAC aleatório. Esses testes são pulados se não houver tela gráfica. |

---

## 7. Estrutura do código

```
NetProbe/
├── scanner.py         parte de REDE, sem interface (dá para usar sozinho)
├── app.py             a JANELA (Tkinter)
└── tests/
    ├── test_scanner.py
    └── test_app.py
```

**`scanner.py`**

| Função | Papel |
|---|---|
| `fazer_ping()` / `interpretar_ping()` | Manda 1 ping e lê o tempo de resposta |
| `sondar_arp()` | ARP Request (SendARP no Windows, UDP + `ip neigh` no Linux) |
| `mac_da_tabela_arp()` / `mac_deste_pc()` | MAC pelo cache ARP / MAC deste PC |
| `verificar_ip()` | Decide se o IP está ocupado: ping primeiro, ARP se falhar |
| `varrer_rede()` | Roda `verificar_ip()` em todos os IPs ao mesmo tempo |
| `porta_aberta()` / `escanear_portas()` | TCP connect em uma porta / em um intervalo |
| `em_paralelo()` | Roda tarefas em várias threads e confere o pedido de parar a cada 0,2 s |
| `redes_sugeridas()` / `ler_rede()` | Descobre a rede deste PC / valida o campo Rede |

**`app.py`:** a classe `NetProbeApp` monta a tela, recebe as mensagens da thread de varredura pela fila e mantém o estado de cada aparelho entre rodadas: status, faltas, MAC anterior e colisões.

---

## 8. Roteiro para a apresentação

**Use o hotspot do celular**, não o Wi-Fi da faculdade. Redes de faculdade costumam isolar os aparelhos uns dos outros (*client isolation*), e nada seria encontrado.

**Preparação**

1. Ligue o hotspot de um celular e conecte nele:
   - o **notebook que roda o NetProbe**;
   - um aparelho que **responde ping** (ex.: outro celular);
   - um aparelho que **bloqueia ping** (ex.: um notebook Windows, que já bloqueia por padrão em rede "Pública").
2. Confira o aparelho que bloqueia ping. Neste comando, a resposta precisa ser "Esgotado o tempo limite":
   ```bash
   ping <ip-dele>
   ```

**Demonstração**

1. Rode `python app.py`, confira se a rede sugerida é a do hotspot e clique em **Iniciar varredura**.
2. **Ping sweep:** mostre a tabela se preenchendo em tempo real e o tempo total no Registro.
3. **ARP:** aponte a linha **amarela**. O aparelho ignorou o ping e mesmo assim foi encontrado pelo ARP.
4. **IP/MAC:** mostre os MACs e a observação "MAC aleatório" dos celulares.
5. **Portas:** mostre as portas abertas, ex.: `53 (DNS)` e `80 (HTTP)` no celular do hotspot.
6. **Tempo real:** marque **Monitorar em tempo real** (ex.: a cada 10 s) e **desligue o Wi-Fi de um aparelho**. Depois de duas rodadas ele fica **vermelho**. Religue e ele volta a ficar verde.
7. **Parâmetros:** mude o **timeout do ping**, a **rede** e o **intervalo de portas** para mostrar que são configuráveis.
8. **Exportar CSV** e abrir o arquivo no Excel.
9. *(Opcional)* **Colisão de IP:** com o monitoramento ligado, desligue um aparelho e, antes que ele fique offline, configure **IP fixo** igual ao dele em outro aparelho. Na rodada seguinte, a linha fica **laranja**.

> Para um aparelho Windows **responder** ping (ou deixar de responder): Firewall do Windows → Configurações avançadas → Regras de entrada → "Compartilhamento de Arquivo e Impressora (Solicitação de Eco - ICMPv4-In)".

---

## 9. Limitações conhecidas

- **Sistemas:** funciona em Windows e Linux. No macOS não foi testado: o `ping` de lá tem outras opções, e o macOS não tem o comando `ip`.
- **Só a rede local:** o ARP não passa pelo roteador. Em outra rede, o ping ainda funciona, mas os aparelhos que bloqueiam ping e os MACs não aparecem.
- **Cache ARP:** um aparelho que acabou de sair pode continuar aparecendo por alguns segundos, porque o sistema guarda os MACs num cache. No Linux o efeito é menor, porque só conta o estado `REACHABLE`, confirmado há pouco tempo.
- **Colisão de IP:** é detectada **entre rodadas**, quando o MAC muda. Sem administrador/root, o sistema entrega só uma resposta ARP por IP. Por isso, dois aparelhos respondendo ao mesmo tempo, na mesma rodada, não são vistos.
- **Portas:** o scan é do tipo *TCP connect*. Portas **UDP** não são testadas, e portas filtradas por firewall aparecem como fechadas.
- **Tamanho da rede:** até 1024 IPs (/22) por varredura.

---

## 10. Uso responsável

Varredura de rede e de portas só deve ser feita em redes que **são suas** ou em que você tem **autorização** para testar, como a rede de casa ou o hotspot do próprio celular. Escanear redes de terceiros sem permissão pode violar políticas de uso e a legislação.
