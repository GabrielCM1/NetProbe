"""
NetProbe - parte de REDE (sem interface).

Aqui ficam as tecnicas de rede do trabalho:
  1. fazer_ping()       -> Varredura ICMP (ping sweep)
  2. sondar_arp()       -> Sondagem ARP para quem nao respondeu ao ping
  3. verificar_ip()     -> junta 1 + 2 e monta o par IP/MAC
  4. escanear_portas()  -> lista as portas TCP abertas de um IP
  5. descobrir_nome(), fabricante(), palpite_tipo() -> identifica QUE aparelho e

Funciona no Windows e no Linux, so com bibliotecas que ja vem com o Python,
e sem precisar de administrador/root.
Pode ser testado sem a interface:  python scanner.py 192.168.15.0/24
"""
# ==========================================================================
# MAPA DESTE ARQUIVO (versão comentada, para estudo)
# ==========================================================================
# A sequência completa de uma varredura, do clique até a tabela:
#
#   varrer_rede(rede)                      <- ponto de entrada (chamado pelo app.py)
#     └─ em_paralelo(...)                  <- roda verificar_ip() em 256 threads
#          └─ verificar_ip(ip)             <- decide o destino de UM IP:
#               ├─ é o próprio PC?   -> mac_deste_pc()               -> Host
#               ├─ fazer_ping(ip)    -> respondeu? -> pega MAC por ARP -> Host "PING"
#               └─ sondar_arp(ip)    -> respondeu? ------------------> Host "ARP"
#                                       nada?      ------------------> None (sem resposta)
#
#   Depois, para cada Host online (o app.py chama):
#     escanear_portas(ip, inicio, fim)
#       └─ em_paralelo(...)                <- roda porta_aberta() em 200 threads
#            └─ porta_aberta(ip, porta)    <- tenta o handshake TCP
#
#   E para mostrar na tela (o app.py chama):
#     fabricante(mac)        <- procura o prefixo mais específico do MAC na lista do IEEE
#     palpite_sistema(ttl)   <- 64 / 128 / 255 -> Linux / Windows / rede
#
# Ordem das seções neste arquivo:
#   Imports e constantes -> classe Host -> utilitários -> descobrir a rede
#   -> 1. PING -> 2. ARP -> 3. verificar/varrer -> 4. portas -> fabricante
#   -> identificação por nome e serviços -> teste pelo terminal
# ==========================================================================

# --- Bibliotecas usadas (todas já vêm com o Python, nada para instalar) ---
import ctypes                  # chamar funções do Windows escritas em C (SendARP)
import functools               # cache de resultados
import ipaddress               # entender redes e IPs: "192.168.15.0/24", lista de hosts...
import os                      # variáveis de ambiente (usado para forçar inglês no Linux)
import re                      # expressões regulares: achar padrões em texto ("TTL=64")
import socket                  # sockets de rede: TCP (portas), UDP (truques de IP/ARP)
import struct                  # converter IP em bytes/número no formato que o Windows espera
import subprocess              # rodar comandos do sistema (ping, arp, ipconfig, ip)
import sys                     # saber o sistema operacional e ler argumentos do terminal
import threading               # trava (Lock) para várias threads não brigarem
import time                    # medir tempo e esperar
from pathlib import Path       # montar o caminho do arquivo fabricantes.txt
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait   # pool de threads
from dataclasses import dataclass, field   # criar a "ficha" Host com pouco código
from typing import Callable, Dict, List, Optional, Set, Tuple   # só anotações de tipo (não mudam nada)

# True se estiver rodando no Windows. Todo "if WINDOWS:" no arquivo escolhe
# entre o jeito Windows e o jeito Linux de fazer a mesma coisa.
WINDOWS = sys.platform.startswith("win")

# Evita que cada "ping" abra uma janela preta de terminal no Windows.
# É uma "bandeira" do Windows passada ao criar o processo.
SEM_JANELA = 0x08000000  # CREATE_NO_WINDOW

# Nomes conhecidos de algumas portas, só para exibir na tela.
# Não influencia a varredura: a porta é testada do mesmo jeito tendo nome ou não.
SERVICOS = {
    20: "FTP-dados", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 515: "Impressora", 548: "AFP (Mac)", 554: "RTSP",
    631: "Impressora", 1883: "MQTT (IoT)", 1900: "UPnP",
    3306: "MySQL", 3389: "Área Remota", 5000: "UPnP/Flask", 5357: "WSD",
    7000: "AirPlay", 8008: "Chromecast", 8009: "Chromecast", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9100: "Impressora", 62078: "iPhone-sync",
}


# --------------------------------------------------------------------------
# A "ficha" de cada aparelho encontrado
# --------------------------------------------------------------------------
# @dataclass gera sozinho o construtor: Host("192.168.15.7", "CC-B0-...", "PING", 1.0)
# Os campos com "=" têm valor padrão e podem ser omitidos.
@dataclass
class Host:
    """Um dispositivo encontrado na rede."""
    ip: str
    mac: Optional[str]          # endereço físico, ex.: A4-5E-60-12-34-56 (None se não deu)
    metodo: str                 # "PING" (respondeu ao ping) ou "ARP" (bloqueia ping)
    tempo_ms: Optional[float]   # tempo de resposta do ping (None se veio do ARP)
    este_pc: bool = False       # True se for o proprio computador que esta varrendo
    portas: List[int] = field(default_factory=list)
    ttl: Optional[int] = None   # TTL da resposta do ping (da uma pista do sistema operacional)
    nome: Optional[str] = None
    modelo: Optional[str] = None
    servicos: Set[str] = field(default_factory=set)
    portas_extras: List[int] = field(default_factory=list)

    @property
    def fabricante(self) -> Optional[str]:
        return fabricante(self.mac)


# --------------------------------------------------------------------------
# Utilitários (usados por várias partes)
# --------------------------------------------------------------------------
def _executar(comando: List[str], timeout: float = 10) -> Optional[str]:
    """Roda um comando do sistema e devolve o que ele imprimiu (ou None se falhar).
    No Windows esconde a janela do terminal; no Linux forca mensagens em ingles
    (LC_ALL=C) para o texto ser sempre o mesmo, qualquer que seja o idioma do sistema."""
    # Passo 1: monta as opções extras de cada sistema.
    extra = {}
    if WINDOWS:
        extra["creationflags"] = SEM_JANELA            # sem janela preta piscando
    else:
        extra["env"] = dict(os.environ, LC_ALL="C")    # textos sempre em inglês
    # Passo 2: roda o comando e captura o que ele imprimiu.
    # Se demorar mais que 'timeout' ou o comando não existir, devolve None.
    try:
        r = subprocess.run(comando, capture_output=True, timeout=timeout, **extra)
    except (subprocess.TimeoutExpired, OSError):
        return None
    # Passo 3: converte os bytes em texto. O terminal do Windows em português usa a
    # codificação "cp850"; o Linux usa UTF-8. errors="ignore" pula caracteres estranhos.
    return r.stdout.decode("cp850" if WINDOWS else "utf-8", errors="ignore")


def normalizar_mac(texto: Optional[str]) -> Optional[str]:
    """'a4:5e:60:12:34:56' ou 'a4-5e-...' -> 'A4-5E-60-12-34-56'.
    Devolve None para MACs que nao sao de um aparelho (tudo 0 ou broadcast)."""
    # Por que existe: o Windows escreve MAC com "-" e o Linux com ":". Para comparar
    # MACs (ex.: na colisão de IP) todos precisam estar no MESMO formato.
    if not texto:
        return None
    # Passo 1: quebra nos separadores ":" ou "-" -> ["a4", "5e", "60", ...]
    partes = re.split(r"[:-]", texto.strip())
    # Passo 2: precisa ter exatamente 6 pedaços, cada um com 1 ou 2 dígitos hexadecimais.
    if len(partes) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in partes):
        return None
    # Passo 3: completa com zero à esquerda ("1" -> "01"), põe em maiúsculas e junta com "-".
    mac = "-".join(p.zfill(2).upper() for p in partes)
    # Passo 4: descarta MACs que não são de um aparelho de verdade:
    # tudo zero (vazio) e tudo FF (endereço de broadcast, "todos da rede").
    if mac in ("00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF"):
        return None
    return mac


def em_paralelo(funcao: Callable, itens, threads: int, parar: Callable[[], bool],
                ao_terminar: Callable) -> bool:
    """Roda funcao(item) para todos os itens ao mesmo tempo e chama
    ao_terminar(item, resultado) a cada um que fica pronto.

    Por que nao um simples 'for tarefa in as_completed(...)'? Porque assim o pedido de
    parar so seria conferido quando algum item terminasse, e na fase do ARP centenas
    de IPs ficam varios segundos sem terminar: o botao Parar demorava ~5 s.
    Com wait(timeout=0.2), o laco "acorda" pelo menos a cada 0,2 s para conferir.

    Ao parar, nao espera os itens que ainda estao rodando (eles terminam sozinhos
    em segundo plano). Devolve True se foi parado antes de acabar."""
    pool = ThreadPoolExecutor(max_workers=threads)
    pendentes = {pool.submit(funcao, item): item for item in itens}   # tarefa -> item
    try:
        while pendentes and not parar():
            prontos, _ = wait(pendentes, timeout=0.2, return_when=FIRST_COMPLETED)
            # Passo 4: para cada tarefa que terminou, tira da lista de pendentes
            # e avisa quem chamou (ao_terminar), com o item e o resultado.
            for tarefa in prontos:
                ao_terminar(pendentes.pop(tarefa), tarefa.result())
    finally:
        pool.shutdown(wait=False, cancel_futures=True)   # cancela o que nem comecou
    return bool(pendentes)


def mac_aleatorio(mac: Optional[str]) -> bool:
    """True se o MAC e "administrado localmente" (bit 0x02 do 1o byte ligado).
    Celulares modernos (Android/iPhone) usam MAC aleatorio por rede, por privacidade."""
    if not mac:
        return False
    try:
        # mac[:2] = primeiro byte em hexa (ex.: "6A"). int(..., 16) converte para número.
        # "& 0x02" testa o 2º bit menos significativo. Ligado = MAC inventado pelo aparelho,
        # desligado = MAC de fábrica (registrado por um fabricante no IEEE).
        # Ex.: 0x6A = 0110 1010 -> bit 0x02 ligado -> aleatório.
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Descobrir a rede local (para sugerir no campo "Rede")
# --------------------------------------------------------------------------
def ips_locais() -> List[str]:
    """IPs IPv4 deste computador (Wi-Fi, cabo, VPN...)."""
    ips = []
    # Truque: "conectar" um socket UDP nao envia nenhum pacote, mas faz o sistema
    # escolher a placa de rede da rota padrao, e assim descobrimos o IP principal.
    # Passo 1: o IP da placa principal (o que tem acesso à internet).
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))     # UDP: connect não manda nada pela rede
            ips.append(s.getsockname()[0])       # "qual IP local você escolheu?"
    except OSError:
        pass
    # Passo 2: todos os outros IPs ligados ao nome do computador (outras placas, VPN...).
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.append(info[4][0])
    except OSError:
        pass
    # dict.fromkeys tira os repetidos mantendo a ordem (o IP da rota padrao fica primeiro)
    return [ip for ip in dict.fromkeys(ips) if not ip.startswith(("127.", "0."))]


def redes_sugeridas() -> List[str]:
    """Transforma cada IP local numa rede /24, colocando as redes de casa
    (192.168.x.x, 10.x.x.x, 172.16-31.x.x) primeiro. Ex.: 192.168.15.6 -> 192.168.15.0/24"""
    redes = dict.fromkeys(str(ipaddress.ip_network(ip + "/24", strict=False)) for ip in ips_locais())
    # sorted e estavel: as privadas (False) vem antes, sem mudar a ordem entre elas
    return sorted(redes, key=lambda r: not ipaddress.ip_network(r).is_private)


def ler_rede(texto: str) -> ipaddress.IPv4Network:
    """Converte '192.168.15.0/24' (ou so '192.168.15.0') num objeto de rede.
    Gera ValueError com mensagem clara se estiver errado."""
    # Passo 1: tira espaços e, se não tiver "/", assume /24 (254 IPs).
    texto = texto.strip()
    if "/" not in texto:
        texto += "/24"
    # Passo 2: deixa a biblioteca ipaddress validar. Se for lixo ("abc", "300.1.1.0"),
    # ela gera ValueError e nós trocamos por uma mensagem em português.
    try:
        rede = ipaddress.IPv4Network(texto, strict=False)
    except ValueError:
        raise ValueError("Rede inválida. Use o formato 192.168.0.0/24")
    # Passo 3: limite de tamanho, para ninguém varrer uma /16 (65 mil IPs) sem querer.
    if rede.num_addresses > 1024:
        raise ValueError("Rede grande demais. Use /22 ou menor (até 1024 IPs), ex.: /24")
    return rede


# --------------------------------------------------------------------------
# 1. PING (ICMP Echo Request / Echo Reply)
# --------------------------------------------------------------------------
# O ping manda um pacote ICMP "Echo Request" (camada 3). Quem está ligado e não
# bloqueia ICMP devolve um "Echo Reply". Não montamos o pacote na mão porque isso
# exige raw socket (administrador); usamos o comando ping do sistema, que manda
# exatamente o mesmo pacote, e lemos o texto que ele imprime.
def interpretar_ping(saida: Optional[str]) -> Optional[float]:
    """Le a saida do comando ping e devolve o tempo em ms, ou None se nao houve resposta.

    So conta como resposta se tiver 'TTL=', porque o ping tambem imprime
    'Host de destino inacessivel' / 'Destination Host Unreachable' (sem TTL)
    quando ninguem responde. Formatos aceitos:
      Windows:  'Resposta de 192.168.0.1: bytes=32 tempo=4ms TTL=64'   (ou 'tempo<1ms')
      Linux:    '64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=2.87 ms'"""
    # Passo 1: sem texto, ou sem "TTL=" (em maiúsculas para pegar o "ttl=" do Linux),
    # quer dizer que não houve Echo Reply.
    if not saida or "TTL=" not in saida.upper():
        return None
    # Passo 2: acha o tempo. A expressão procura "=" ou "<", um número (com ou sem
    # decimal, com ponto ou vírgula) e depois "ms". Pega "=4ms", "<1ms", "=2.87 ms".
    m = re.search(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", saida)
    # Passo 3: converte para número (trocando vírgula por ponto). Se respondeu mas não
    # achou o tempo, devolve 0.0 (respondeu, tempo desconhecido).
    return float(m.group(1).replace(",", ".")) if m else 0.0


def interpretar_ttl(saida: Optional[str]) -> Optional[int]:
    """'... TTL=128' (Windows) ou '... ttl=64 ...' (Linux) -> 128 / 64."""
    # Procura "TTL=" seguido de dígitos, sem diferenciar maiúscula/minúscula (re.I).
    m = re.search(r"TTL=(\d+)", saida or "", re.I)
    return int(m.group(1)) if m else None


def palpite_sistema(ttl: Optional[int]) -> str:
    """Cada sistema comeca o TTL num valor: 64 (Linux, Android, iPhone, Mac),
    128 (Windows) ou 255 (roteadores e equipamentos de rede). Cada roteador no
    caminho tira 1, mas numa rede local o valor chega quase igual ao inicial."""
    # Usa faixas em vez de valores exatos porque o TTL pode chegar 1 ou 2 abaixo
    # do inicial se houver algum roteador no meio.
    if not ttl:
        return ""
    if ttl > 128:                 # 129 a 255 -> começou em 255
        return "equipamento de rede"
    if ttl > 64:                  # 65 a 128  -> começou em 128
        return "Windows"
    return "Linux/Android/Apple"  # até 64    -> começou em 64


def fazer_ping(ip: str, timeout_ms: int) -> Optional[Tuple[float, Optional[int]]]:
    """Manda 1 ping. Devolve (tempo de resposta em ms, TTL), ou None se nao respondeu.

    Windows:  ping -n 1 -w <ms>  (um pacote, timeout em milissegundos)
    Linux:    ping -c 1 -W <s>   (um pacote, timeout em segundos, aceita fracao)"""
    # Passo 1: monta o comando certo para o sistema. O timeout vem do campo da tela.
    if WINDOWS:
        comando = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        comando = ["ping", "-c", "1", "-n", "-W", "%.3f" % (timeout_ms / 1000), ip]
    # Passo 2: roda. O limite do processo é o timeout do ping + 3 s de folga,
    # só para o programa nunca ficar preso se o comando travar.
    saida = _executar(comando, timeout=timeout_ms / 1000 + 3)
    # Passo 3: lê o tempo. Se não respondeu, devolve None; se respondeu, devolve
    # o par (tempo, TTL).
    tempo = interpretar_ping(saida)
    return None if tempo is None else (tempo, interpretar_ttl(saida))


# --------------------------------------------------------------------------
# 2. ARP (Address Resolution Protocol)
# --------------------------------------------------------------------------
# A ideia: um ARP Request pergunta para a rede inteira "Quem tem o IP X? Me diga seu MAC."
# Se o dispositivo existe, ele PRECISA responder (senão não conseguiria usar a rede),
# mesmo que o firewall dele bloqueie ping. É isso que descobre quem "se esconde".
#
# WINDOWS: SendARP é uma função do próprio Windows (iphlpapi.dll) que manda o ARP
#          e devolve o MAC. Não precisa de administrador.
# LINUX:   sem root não dá para montar o pacote ARP na mão. Então mandamos um
#          datagrama UDP qualquer para o IP: para entregá-lo, o kernel PRECISA
#          descobrir o MAC e envia ele mesmo o ARP Request. Depois lemos o
#          resultado na tabela de vizinhos (ip neigh): REACHABLE = respondeu,
#          FAILED = ninguém respondeu.
#
# Este bloco roda UMA vez, quando o arquivo é carregado: prepara a função SendARP.
try:
    _iphlpapi = ctypes.windll.iphlpapi        # abre a biblioteca de rede do Windows
    # Diz ao Python os tipos de cada parâmetro da função em C:
    #   SendARP(IP destino, IP origem, ponteiro para o MAC, ponteiro para o tamanho)
    _iphlpapi.SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                  ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    _iphlpapi.SendARP.restype = ctypes.c_ulong   # devolve um número: 0 = sucesso
except AttributeError:  # não é Windows (ctypes.windll só existe no Windows)
    _iphlpapi = None


def _sondar_arp_windows(ip: str, tentativas: int) -> Optional[str]:
    # Assinatura em C:  DWORD SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen)
    # O ctypes precisa receber cada parametro no formato da linguagem C:
    #   - DestIP: o IP como um inteiro de 32 bits, na ordem de bytes da rede;
    #   - SrcIP = 0: "escolha voce a placa de rede";
    #   - pMacAddr: um vetor de 6 bytes onde o Windows escreve o MAC;
    #   - PhyAddrLen: entra 6 (tamanho do vetor) e sai quantos bytes foram escritos.
    if _iphlpapi is None:
        return None
    # Passo 1: converte "192.168.15.7" em 4 bytes (inet_aton) e depois num único
    # número de 32 bits (struct.unpack), que é o formato que a SendARP espera.
    destino = struct.unpack("=I", socket.inet_aton(ip))[0]   # IP no formato que o Windows espera
    for _ in range(tentativas):
        # Passo 2: prepara um espaço vazio de 6 bytes para o Windows escrever o MAC,
        # e uma variável com o tamanho desse espaço (6).
        mac = (ctypes.c_ubyte * 6)()                         # espaço para os 6 bytes do MAC
        tamanho = ctypes.c_ulong(6)
        # Passo 3: chama a função. byref() passa o "endereço" das variáveis, para o
        # Windows poder escrever nelas. O 0 no IP de origem = "escolha você a placa".
        # Aqui o ARP Request sai de verdade pela rede, e a função espera a resposta.
        resultado = _iphlpapi.SendARP(destino, 0, ctypes.byref(mac), ctypes.byref(tamanho))
        if resultado == 0 and tamanho.value == 6:            # 0 = sucesso
            # Passo 4: transforma os 6 bytes em texto: [204, 176, ...] -> "CC-B0-..."
            # "%02X" = 2 dígitos hexadecimais maiúsculos.
            achado = normalizar_mac("-".join("%02X" % b for b in mac[:6]))
            if achado:
                return achado
        # Falhou: tenta de novo (aparelhos "dormindo" às vezes demoram a responder).
    return None


def ler_vizinhos_linux(saida: str) -> Dict[str, Tuple[Optional[str], str]]:
    """Interpreta 'ip -4 neigh show'. Devolve {ip: (mac ou None, estado)}. Exemplos de linha:
      192.168.1.1 dev wlp3s0 lladdr f4:e8:4f:98:1b:94 REACHABLE
      192.168.1.9 dev wlp3s0 lladdr 3c:22:fb:00:11:22 router STALE
      192.168.1.50 dev wlp3s0 FAILED"""
    tabela = {}
    for linha in saida.splitlines():
        partes = linha.split()                  # quebra a linha em palavras
        if len(partes) < 2:
            continue
        mac = None
        # O MAC vem logo depois da palavra "lladdr" (link-layer address = MAC).
        if "lladdr" in partes:
            i = partes.index("lladdr")
            if i + 1 < len(partes):
                mac = normalizar_mac(partes[i + 1])
        # 1ª palavra = IP; última palavra = estado (REACHABLE, STALE, FAILED...).
        tabela[partes[0]] = (mac, partes[-1].upper())
    return tabela


# Cache compartilhado da tabela de vizinhos do Linux:
#   _vizinhos_trava: só uma thread por vez pode atualizar o cache.
#   _vizinhos_cache: (hora em que foi lida, tabela).
_vizinhos_trava = threading.Lock()
_vizinhos_cache: Tuple[float, Dict[str, Tuple[Optional[str], str]]] = (0.0, {})


def vizinhos_linux(max_idade: float = 0.25) -> Dict[str, Tuple[Optional[str], str]]:
    """Tabela de vizinhos (cache ARP) do Linux. Como ate 256 threads consultam a tabela
    ao mesmo tempo, ela e lida no maximo a cada 0,25 s e compartilhada entre todas.

    Sem isso, cada thread rodaria o comando 'ip neigh' 4 vezes por segundo:
    ~1000 processos por segundo so para ler a mesma tabela. A trava (Lock) garante
    que so uma thread rode o comando; as outras esperam e usam o mesmo resultado."""
    global _vizinhos_cache
    # Passo 1: pega a trava. Se outra thread estiver lendo, esta espera aqui.
    with _vizinhos_trava:
        lida_em, tabela = _vizinhos_cache
        # Passo 2: só roda o comando de novo se a última leitura tiver mais de 0,25 s.
        # Sem isso seriam centenas de processos "ip neigh" por segundo.
        if time.monotonic() - lida_em > max_idade:
            saida = _executar(["ip", "-4", "neigh", "show"], timeout=5)
            tabela = ler_vizinhos_linux(saida or "")
            _vizinhos_cache = (time.monotonic(), tabela)
        # Passo 3: devolve a tabela (nova ou a recente do cache).
        return tabela


def _provocar_arp(ip: str):
    """Manda 1 datagrama UDP para a porta 9 ('discard'). O conteudo nao importa:
    o objetivo e obrigar o kernel a enviar um ARP Request para esse IP."""
    # Para entregar qualquer pacote na rede local, o Linux precisa do MAC do destino.
    # Se não sabe, ele mesmo manda o ARP Request. É assim que fazemos ARP sem root.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"NetProbe", (ip, 9))
    except OSError:
        pass


def _sondar_arp_linux(ip: str, tentativas: int) -> Optional[str]:
    # Cada tentativa: o kernel manda 3 ARP Requests (1 por segundo). Se o IP já estava
    # na tabela como STALE (visto há algum tempo), o kernel espera ~5 s antes de
    # reconfirmar, por isso o limite de 9 s.
    # Estados da tabela de vizinhos que importam aqui:
    #   INCOMPLETE -> ARP enviado, esperando resposta    REACHABLE -> respondeu agora ha pouco
    #   STALE/DELAY/PROBE -> conhecido, sendo reconfirmado  FAILED  -> ninguem respondeu
    #   (sem entrada) -> o kernel nem tentou: o IP nao esta na rede local
    for _ in range(tentativas):
        inicio = time.monotonic()
        # Passo 1: provoca o ARP mandando um pacote UDP qualquer.
        _provocar_arp(ip)
        # Passo 2: a cada 0,25 s, olha a tabela de vizinhos para ver o que aconteceu.
        while time.monotonic() - inicio < 9:
            time.sleep(0.25)
            mac, estado = vizinhos_linux().get(ip, (None, ""))
            passou = time.monotonic() - inicio
            if estado in ("REACHABLE", "PERMANENT") and mac:
                return mac                                    # respondeu ao ARP
            if not estado and passou > 1.5:
                return None                                   # fora da rede local: não há ARP
            if estado == "FAILED" and passou > 1.0:
                break                                         # ninguém respondeu
        # Passo 3: se chegou aqui, não respondeu nesta tentativa; tenta de novo.
    return None


def sondar_arp(ip: str, tentativas: int = 2) -> Optional[str]:
    """Manda um ARP Request para o IP. Devolve o MAC (ex.: 'A4-5E-60-12-34-56') ou None.
    Tenta 2 vezes: celulares em modo economia as vezes demoram a responder."""
    # Só escolhe o jeito certo para o sistema. O resto do programa chama sempre esta.
    if WINDOWS:
        return _sondar_arp_windows(ip, tentativas)
    return _sondar_arp_linux(ip, tentativas)


def ler_arp_windows(saida: str, ip: str) -> Optional[str]:
    """Procura o MAC do IP na saida do 'arp -a' do Windows. Exemplo de linha:
      192.168.15.1          a4-5e-60-12-34-56     dinâmico"""
    # A expressão procura: o IP exato (sem número ou ponto colado antes, para
    # "192.168.15.1" não casar dentro de "192.168.15.10"), espaços, e um MAC
    # no formato xx-xx-xx-xx-xx-xx.
    m = re.search(r"(?<![\d.])" + re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", saida, re.I)
    return normalizar_mac(m.group(1)) if m else None


def mac_da_tabela_arp(ip: str) -> Optional[str]:
    """Le a tabela ARP do sistema, onde ficam guardados os MACs que o
    computador ja descobriu recentemente (por exemplo, durante o ping)."""
    # Plano B para pegar o MAC: o sistema guarda os MACs que já descobriu.
    if WINDOWS:
        saida = _executar(["arp", "-a", ip])
        return ler_arp_windows(saida, ip) if saida else None
    mac, estado = vizinhos_linux().get(ip, (None, ""))
    return mac if estado not in ("FAILED", "INCOMPLETE") else None


def mac_deste_pc(ip: str) -> Optional[str]:
    """O ARP nao funciona para o proprio IP, entao perguntamos ao sistema qual e o MAC
    da placa de rede que tem esse IP (Windows: 'ipconfig /all'; Linux: 'ip addr')."""
    if WINDOWS:
        # Passo 1: o ipconfig /all lista todas as placas de rede, uma em cada bloco.
        saida = _executar(["ipconfig", "/all"]) or ""
        # Passo 2: separa os blocos (cada um começa numa linha sem espaço na frente).
        for bloco in re.split(r"\r?\n(?=\S)", saida):        # um bloco por placa de rede
            # Passo 3: acha o bloco que contém o nosso IP...
            if re.search(r"(?<![\d.])" + re.escape(ip) + r"(?![\d])", bloco):
                # ...e pega o primeiro MAC desse bloco ("Endereço Físico").
                m = re.search(r"([0-9A-F]{2}(?:-[0-9A-F]{2}){5})", bloco, re.I)
                if m:
                    return normalizar_mac(m.group(1))
        return None
    # Linux: "ip -o addr" dá uma linha por endereço, com o nome da placa (ex.: wlp3s0).
    # O MAC dessa placa está no arquivo /sys/class/net/<placa>/address.
    for linha in (_executar(["ip", "-o", "-4", "addr", "show"]) or "").splitlines():
        p = linha.split()                 # ex.: 3: wlp3s0  inet 192.168.1.154/24 brd ...
        if len(p) >= 4 and p[3].split("/")[0] == ip:
            try:
                with open("/sys/class/net/%s/address" % p[1].rstrip(":").split("@")[0]) as f:
                    return normalizar_mac(f.read())
            except OSError:
                return None
    return None


# --------------------------------------------------------------------------
# 3. Verificar um IP: ping primeiro, ARP se o ping falhar
# --------------------------------------------------------------------------
def verificar_ip(ip: str, timeout_ms: int, meus_ips: List[str]) -> Optional[Host]:
    """Decide se existe um dispositivo neste IP.

    - Respondeu ao ping           -> online, metodo PING (ainda pegamos o MAC via ARP)
    - Nao respondeu, mas ARP sim  -> online, metodo ARP (o dispositivo bloqueia ping)
    - Nenhum dos dois             -> IP vazio, devolve None"""
    # ESTA É A FUNÇÃO CENTRAL. Roda uma vez para cada IP, em paralelo.
    #
    # Passo 1: é o próprio computador? Não faz sentido pingar a si mesmo;
    # o MAC sai do ipconfig / ip addr.
    if ip in meus_ips:
        return Host(ip, mac_deste_pc(ip), "PING", 0, este_pc=True, nome=socket.gethostname())

    # Passo 2: tenta o PING (elemento 1).
    resposta = fazer_ping(ip, timeout_ms)
    if resposta is not None:
        tempo, ttl = resposta
        # Ja sabemos que existe. O ping ja fez o ARP, entao o MAC esta no cache.
        # A ordem muda por sistema so por custo: no Windows o SendARP ja consulta o cache
        # e e uma chamada de funcao (barata), enquanto 'arp -a' abre um processo.
        # No Linux e o contrario: a tabela de vizinhos ja esta lida (cache de 0,25 s).
        if WINDOWS:
            mac = sondar_arp(ip, tentativas=2) or mac_da_tabela_arp(ip)
        else:
            mac = mac_da_tabela_arp(ip) or sondar_arp(ip, tentativas=1)
        return Host(ip, mac, "PING", tempo, ttl=ttl)

    # Passo 3: não respondeu ao ping. Tenta o ARP (elemento 2).
    # Se o aparelho existe, ele É OBRIGADO a responder ARP, mesmo bloqueando ping.
    mac = sondar_arp(ip, tentativas=2)   # 2 tentativas: aparelhos dormindo demoram a responder
    if mac is not None:
        return Host(ip, mac, "ARP", None)
    # Passo 4: nem ping nem ARP: o IP está vazio mesmo.
    return None


def varrer_rede(rede: ipaddress.IPv4Network, timeout_ms: int,
                ao_verificar: Callable[[str, Optional[Host]], None],
                parar: Callable[[], bool] = lambda: False,
                threads: int = 256) -> List[Host]:
    """Verifica todos os IPs da rede AO MESMO TEMPO (varias threads).

    Sem threads, 254 IPs x (timeout do ping + ~6 s de ARP) = mais de 25 minutos.
    Com 256 threads, os 254 IPs de uma rede /24 sao testados todos juntos.
    'ao_verificar(ip, host)' e chamado a cada IP terminado (para a tela atualizar na hora)."""
    # Passo 1: descobre os IPs do próprio PC uma vez só (verificar_ip precisa saber).
    meus_ips = ips_locais()
    encontrados = []

    # Passo 2: o que fazer cada vez que um IP termina: guarda se achou aparelho
    # e avisa a tela (ao_verificar), que é o que faz a tabela encher em tempo real.
    def terminou(ip, host):
        if host:
            encontrados.append(host)
        ao_verificar(ip, host)

    # Passo 3: roda verificar_ip() para todos os IPs da rede ao mesmo tempo.
    # rede.hosts() já pula o endereço da rede (.0) e o de broadcast (.255).
    em_paralelo(lambda ip: verificar_ip(ip, timeout_ms, meus_ips),
                [str(ip) for ip in rede.hosts()], threads, parar, terminou)
    # Passo 4: os resultados chegam fora de ordem (cada IP termina num tempo);
    # ordena pelo IP antes de devolver.
    encontrados.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return encontrados


# --------------------------------------------------------------------------
# 4. Portas abertas (TCP connect scan)
# --------------------------------------------------------------------------
def porta_aberta(ip: str, porta: int, timeout_ms: int) -> bool:
    """Tenta abrir uma conexao TCP (o 'aperto de mao' de 3 vias: SYN, SYN-ACK, ACK).
    Se conectar, tem um programa escutando ali: a porta esta ABERTA."""
    try:
        # AF_INET = IPv4; SOCK_STREAM = TCP.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_ms / 1000)      # o socket usa segundos
            # connect_ex tenta conectar e devolve um código em vez de dar erro:
            #   0          -> recebeu SYN-ACK: porta ABERTA
            #   outro nº   -> recebeu RST (fechada) ou estourou o timeout (filtrada)
            return s.connect_ex((ip, porta)) == 0   # 0 = conectou
    except OSError:          # ex.: rede caiu no meio; conta como fechada
        return False


def escanear_portas(ip: str, inicio: int, fim: int, timeout_ms: int,
                    parar: Callable[[], bool] = lambda: False, threads: int = 200) -> List[int]:
    """Testa as portas de 'inicio' ate 'fim' (inclusive), varias ao mesmo tempo."""
    abertas = []
    # Testa todas as portas do intervalo em paralelo (200 ao mesmo tempo).
    # range(inicio, fim + 1): o "+ 1" é porque o range do Python não inclui o último.
    # A cada porta testada, se estiver aberta, guarda na lista.
    em_paralelo(lambda p: porta_aberta(ip, p, timeout_ms), range(inicio, fim + 1), threads, parar,
                lambda p, aberta: abertas.append(p) if aberta else None)
    return sorted(abertas)                      # em ordem crescente para exibir


def nome_porta(p: int) -> str:
    """'80' -> '80 (HTTP)'."""
    nome = SERVICOS.get(p)
    return "%d (%s)" % (p, nome) if nome else str(p)


def texto_tempo(tempo_ms: Optional[float]) -> str:
    """2.87 -> '3 ms';  0.4 -> '<1 ms';  None -> '-'."""
    if tempo_ms is None:
        return "-"
    return "<1 ms" if tempo_ms < 1 else "%d ms" % round(tempo_ms)


# --------------------------------------------------------------------------
# 5. Identificar o aparelho: fabricante, nome e tipo provavel
# --------------------------------------------------------------------------
# Nenhuma destas tecnicas precisa de root, e nenhuma acessa a internet:
#   - FABRICANTE: os 3 primeiros bytes do MAC (OUI) sao registrados por fabricante no IEEE.
#     A lista fica no arquivo fabricantes.txt (gerado por atualizar_fabricantes.py).
#   - NOME: pergunta ao proprio aparelho como ele se chama, por mDNS (celulares, Apple,
#     TVs, Chromecast, impressoras), NetBIOS (Windows) ou DNS reverso (roteador).
#   - TIPO PROVAVEL: um palpite juntando nome, portas abertas, fabricante e TTL.
ARQUIVO_FABRICANTES = Path(__file__).resolve().parent / "fabricantes.txt"


@functools.lru_cache(maxsize=None)    # le o arquivo so na 1a vez; depois devolve o mesmo dicionario
def carregar_fabricantes() -> Dict[str, str]:
    """Le o fabricantes.txt: {'F4E84F': 'ZTE', ...}. Sem o arquivo, fica vazio."""
    tabela = {}
    try:
        with open(ARQUIVO_FABRICANTES, encoding="utf-8") as f:
            for linha in f:
                if not linha.startswith("#"):
                    prefixo, _, nome = linha.rstrip("\n").partition("\t")
                    if nome:
                        tabela[prefixo] = nome
    except OSError:
        pass
    return tabela


def fabricante(mac: Optional[str]) -> Optional[str]:
    """'A8-E6-21-A1-2D-07' -> 'Amazon'. None se nao souber.
    MAC aleatorio nao tem fabricante: ele foi inventado pelo aparelho, por privacidade."""
    if not mac or mac_aleatorio(mac):
        return None
    hexa = mac.replace("-", "").upper()
    tabela = carregar_fabricantes()
    # O IEEE vende blocos de 3 tamanhos: 24 bits (6 digitos hex, o OUI comum), 28 bits (7)
    # e 36 bits (9). Um mesmo prefixo de 6 digitos pode ter sido dividido entre varias
    # empresas pequenas, entao o bloco mais especifico tem que ser procurado primeiro.
    for tamanho in (9, 7, 6):
        nome = tabela.get(hexa[:tamanho])
        if nome:
            return nome
    return None


def texto_fabricante(mac: Optional[str]) -> str:
    """O que mostrar na coluna Fabricante: o nome, 'MAC aleatório (privado)' ou '-'."""
    if mac_aleatorio(mac):
        return "MAC aleatório (privado)"
    return fabricante(mac) or "-"


def _nome_dns(dados: bytes, pos: int) -> Tuple[str, int]:
    """Le um nome no formato DNS ('\\x07Android\\x05local\\x00', com compressao).
    Devolve (nome, posicao logo depois dele).

    No pacote DNS, 'Android.local' vira: [7]Android[5]local[0], ou seja, cada pedaco
    vem precedido do seu tamanho, e o 0 marca o fim. Para economizar espaco existe a
    COMPRESSAO: um byte com os 2 bits de cima ligados (0xC0) e um ponteiro, que diz
    "o resto do nome esta na posicao X do pacote". Por isso guardamos 'depois':
    a leitura continua em X, mas o proximo campo do pacote comeca logo apos o ponteiro."""
    partes, depois = [], None
    for _ in range(128):                         # protege contra pacote malformado
        n = dados[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:                     # ponteiro: o resto do nome esta em outro lugar
            if depois is None:
                depois = pos + 2
            pos = ((n & 0x3F) << 8) | dados[pos + 1]
            continue
        partes.append(dados[pos + 1:pos + 1 + n].decode("utf-8", errors="ignore"))
        pos += 1 + n
    return ".".join(partes), (depois if depois is not None else pos)


PTR, TXT = 12, 16      # tipos de registro DNS usados aqui


def pergunta_dns(nomes: List[str], tipo: int = PTR) -> bytes:
    """Monta um pacote de pergunta DNS/mDNS com uma pergunta para cada nome."""
    corpo = b""
    for nome in nomes:
        corpo += b"".join(bytes([len(p)]) + p.encode() for p in nome.split(".")) + b"\x00"
        corpo += struct.pack(">HH", tipo, 0x8001)   # classe 0x8001 = IN + "responda direto para mim"
    # cabecalho: id 0, flags 0, N perguntas, 0 respostas
    return struct.pack(">HHHHHH", 0, 0, len(nomes), 0, 0, 0) + corpo


def pergunta_mdns(ip: str) -> bytes:
    """Pergunta PTR reversa: 'qual o nome de 18.1.168.192.in-addr.arpa?'"""
    return pergunta_dns([".".join(reversed(ip.split("."))) + ".in-addr.arpa"])


def registros_dns(dados: bytes) -> List[Tuple[str, int, int, int]]:
    """Todos os registros de uma resposta DNS: (nome, tipo, inicio dos dados, tamanho).

    PULA a secao de perguntas de proposito: numa resposta mDNS "legacy unicast" o
    aparelho repete as perguntas que recebeu. Se lessemos tudo, cada aparelho pareceria
    anunciar todos os servicos que perguntamos (foi o que aconteceu num teste real).
    Gera IndexError/struct.error se o pacote estiver quebrado."""
    perguntas, respostas, autoridade, adicionais = struct.unpack(">HHHH", dados[4:12])
    pos = 12
    for _ in range(perguntas):
        pos = _nome_dns(dados, pos)[1] + 4            # nome + tipo (2) + classe (2)
    registros = []
    for _ in range(respostas + autoridade + adicionais):
        nome, pos = _nome_dns(dados, pos)
        tipo, _, _, tamanho = struct.unpack(">HHIH", dados[pos:pos + 10])   # tipo, classe, TTL, tamanho
        pos += 10
        registros.append((nome, tipo, pos, tamanho))
        pos += tamanho
    return registros


def interpretar_mdns(dados: bytes) -> Optional[str]:
    """Tira o nome da resposta mDNS (o primeiro registro PTR). Ex.: 'Android.local'."""
    try:
        for _, tipo, inicio, _ in registros_dns(dados):
            if tipo == PTR:
                return _nome_dns(dados, inicio)[0]
    except (IndexError, struct.error):
        pass
    return None


def interpretar_netbios(dados: bytes) -> Optional[str]:
    """Tira o nome do computador da resposta NetBIOS 'Node Status'.
    Os primeiros 56 bytes sao fixos (cabecalho + nome perguntado + tipo/classe/TTL/tamanho);
    o byte 56 diz quantos nomes vem a seguir. Cada nome ocupa 18 bytes:
    15 do nome + 1 de sufixo + 2 de flags. O nome do computador e o de sufixo 0x00
    que nao e de grupo (o de grupo, flag 0x8000, e o do grupo de trabalho, ex.: WORKGROUP)."""
    try:
        quantos = dados[56]
        for i in range(quantos):
            e = dados[57 + 18 * i:57 + 18 * (i + 1)]
            nome = e[:15].decode("ascii", errors="ignore").strip()
            if nome and e[15] == 0x00 and not (struct.unpack(">H", e[16:18])[0] & 0x8000):
                return nome
    except (IndexError, struct.error):
        pass
    return None


def _perguntar_udp(ip: str, porta: int, pacote: bytes, timeout: float) -> Optional[bytes]:
    """Manda 1 pacote UDP e espera a resposta DESSE ip (ignora pacotes de outros)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pacote, (ip, porta))
            while True:
                dados, origem = s.recvfrom(4096)
                if origem[0] == ip:
                    return dados
    except OSError:                     # timeout, porta fechada, rede inacessivel...
        return None


def nome_mdns(ip: str, timeout: float = 1.0) -> Optional[str]:
    dados = _perguntar_udp(ip, 5353, pergunta_mdns(ip), timeout)
    return interpretar_mdns(dados) if dados else None


def nome_netbios(ip: str, timeout: float = 0.8) -> Optional[str]:
    # Pergunta "Node Status" (tipo 0x21): "me diga todos os seus nomes".
    # O nome perguntado e o curinga '*'. O NetBIOS codifica cada byte do nome em 2 letras
    # (metade de cima e metade de baixo + 'A'): '*' = 0x2A -> 'C','K', e o resto do nome
    # (15 bytes zero) vira 'AA' 15 vezes. Resultado: 'CK' + 30 'A', com tamanho 32 (0x20).
    pacote = (struct.pack(">HHHHHH", 0x4E50, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30
              + b"\x00" + struct.pack(">HH", 0x21, 1))
    dados = _perguntar_udp(ip, 137, pacote, timeout)
    return interpretar_netbios(dados) if dados else None


def nome_dns_reverso(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


# Nomes provisorios que alguns aparelhos anunciam quando nao tem nome configurado
_NOMES_VAZIOS = {"localhost", "none", "(none)", "unknown", "null", "default", "spotifyconnect"}


def limpar_nome(nome: Optional[str], ip: str) -> Optional[str]:
    """'Android.local' -> 'Android'. Descarta nomes que nao dizem nada
    ('localhost', 'none', '_gateway', o proprio IP, '192-168-1-18.provedor.com')."""
    if not nome:
        return None
    nome = nome.strip().rstrip(".")
    for sufixo in (".local", ".lan", ".home", ".localdomain", ".home.arpa"):
        if nome.lower().endswith(sufixo):
            nome = nome[: -len(sufixo)]
    if (not nome or nome.startswith("_") or nome.lower() in _NOMES_VAZIOS
            or re.fullmatch(r"[\d.\-]+", nome) or ip.replace(".", "-") in nome or ip in nome):
        return None
    return nome


def descobrir_nome(ip: str) -> Optional[str]:
    """Tenta mDNS, depois NetBIOS, depois DNS reverso. Devolve o primeiro nome util."""
    for metodo in (nome_mdns, nome_netbios, nome_dns_reverso):
        nome = limpar_nome(metodo(ip), ip)
        if nome:
            return nome
    return None


# --------------------------------------------------------------------------
# Servicos mDNS da rede inteira (DNS-SD / Bonjour)
# --------------------------------------------------------------------------
# Em vez de perguntar a cada aparelho "qual o seu nome?", perguntamos a REDE INTEIRA
# (endereco multicast 224.0.0.251) "quem oferece estes servicos?". Isso pega aparelhos
# que nao respondem a pergunta direta, como iPhones e Macs, e revela:
#   - o SERVICO: '_companion-link' e '_apple-mobdev2' so existem em aparelhos Apple,
#     '_googlecast' em Chromecast, '_ipp' em impressoras, '_airplay' em quem recebe AirPlay;
#   - o NOME AMIGAVEL que o dono deu: 'TV Sala', 'iPhone de Ana';
#   - o MODELO, no registro TXT: 'model=iPhone14,5', 'rpMd=MacBookPro18,1', 'md=Chromecast'.
# Funciona mesmo com MAC aleatorio. Mas um iPhone com a tela apagada "dorme" e nao responde.
SERVICOS_MDNS = [
    "_services._dns-sd._udp.local",     # "liste todos os seus servicos"
    "_companion-link._tcp.local", "_apple-mobdev2._tcp.local", "_device-info._tcp.local",
    "_airplay._tcp.local", "_raop._tcp.local", "_homekit._tcp.local", "_hap._tcp.local",
    "_googlecast._tcp.local", "_spotify-connect._tcp.local",
    "_ipp._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local",
    "_smb._tcp.local", "_workstation._tcp.local",
]
_CHAVES_MODELO = ("model", "rpMd", "md", "am", "ty")   # chaves do TXT que trazem o modelo


@dataclass
class InfoMdns:
    """O que um aparelho anunciou por mDNS."""
    servicos: Set[str] = field(default_factory=set)    # ex.: {'_airplay', '_raop'}
    nome: Optional[str] = None                         # ex.: 'TV Sala'
    modelo: Optional[str] = None                       # ex.: 'iPhone14,5'


def _servico_de(nome: str) -> Optional[str]:
    """'TV Sala._airplay._tcp.local' ou '_airplay._tcp.local' -> '_airplay'."""
    m = re.search(r"(_[^.]+)\._(?:tcp|udp)\.local$", nome)
    return m.group(1) if m else None


def _ler_txt(dados: bytes, inicio: int, tamanho: int) -> Dict[str, str]:
    """Registro TXT: varias strings 'chave=valor', cada uma precedida do seu tamanho."""
    pares, pos, fim = {}, inicio, inicio + tamanho
    while pos < fim:
        n = dados[pos]
        texto = dados[pos + 1:pos + 1 + n].decode("utf-8", errors="ignore")
        chave, _, valor = texto.partition("=")
        pares[chave] = valor
        pos += 1 + n
    return pares


def interpretar_servicos_mdns(dados: bytes) -> InfoMdns:
    """Le uma resposta mDNS e junta servicos, nome amigavel e modelo anunciados."""
    info = InfoMdns()
    try:
        for nome, tipo, inicio, tamanho in registros_dns(dados):
            if tipo == PTR:
                alvo = _nome_dns(dados, inicio)[0]
                if nome == "_services._dns-sd._udp.local":       # lista de servicos
                    servico = _servico_de(alvo)
                else:                                            # instancia: 'TV Sala._airplay._tcp.local'
                    servico = _servico_de(nome)
                    instancia = alvo[: -len(nome) - 1] if alvo.endswith("." + nome) else ""
                    # AirPlay de audio (_raop) usa 'MAC@Nome'; tira a parte antes do @
                    instancia = instancia.split("@", 1)[-1]
                    if instancia and not info.nome and not re.fullmatch(r"[0-9A-Fa-f-]{12,}", instancia):
                        info.nome = instancia
                if servico:
                    info.servicos.add(servico)
            elif tipo == TXT:
                txt = _ler_txt(dados, inicio, tamanho)
                if txt.get("fn"):                    # Chromecast: 'fn' e o nome amigavel
                    info.nome = txt["fn"]
                for chave in _CHAVES_MODELO:
                    if txt.get(chave) and not info.modelo:
                        info.modelo = txt[chave]
    except (IndexError, struct.error):
        pass
    return info


def descobrir_servicos_mdns(espera: float = 3.0, parar: Callable[[], bool] = lambda: False,
                            destino: Tuple[str, int] = ("224.0.0.251", 5353)) -> Dict[str, InfoMdns]:
    """Pergunta para a rede inteira quem oferece os SERVICOS_MDNS e espera 'espera' segundos.
    Devolve {ip: InfoMdns} de quem respondeu. 'destino' so muda nos testes."""
    resultado: Dict[str, InfoMdns] = {}
    # As perguntas vao em pacotes de 5, para nenhum pacote ficar grande demais
    pacotes = [pergunta_dns(SERVICOS_MDNS[i:i + 5]) for i in range(0, len(SERVICOS_MDNS), 5)]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)   # exigido pelo mDNS
            s.settimeout(0.2)
            for _ in range(2):              # manda 2 vezes: UDP pode perder pacote
                for pacote in pacotes:
                    s.sendto(pacote, destino)
            fim = time.monotonic() + espera
            while time.monotonic() < fim and not parar():
                try:
                    dados, origem = s.recvfrom(9000)
                except socket.timeout:
                    continue
                info = interpretar_servicos_mdns(dados)
                junto = resultado.setdefault(origem[0], InfoMdns())
                junto.servicos |= info.servicos
                junto.nome = junto.nome or info.nome
                junto.modelo = junto.modelo or info.modelo
    except OSError:                         # sem rede, multicast bloqueado...
        pass
    return {ip: i for ip, i in resultado.items() if i.servicos or i.nome or i.modelo}


def aplicar_mdns(h: Host, info: InfoMdns):
    """Junta no Host o que ele anunciou por mDNS. O nome amigavel ('TV Sala') tem
    preferencia sobre o nome tecnico do aparelho ('Android', 'localhost')."""
    h.servicos |= info.servicos
    h.modelo = info.modelo or h.modelo
    h.nome = limpar_nome(info.nome, h.ip) or h.nome


# --------------------------------------------------------------------------
# Portas de identificacao
# --------------------------------------------------------------------------
# Algumas portas "entregam" o tipo de aparelho, mas ficam fora do intervalo padrao (1-1024).
# Elas sao testadas sempre, a parte, so para o palpite: nao entram em "Portas abertas",
# que continua mostrando exatamente o intervalo escolhido na tela.
PORTAS_IDENTIFICACAO = [62078, 7000, 8008, 8009, 9100, 631, 548, 3389, 445, 554, 1883]


def escanear_portas_identificacao(ip: str, inicio: int, fim: int, timeout_ms: int,
                                  parar: Callable[[], bool] = lambda: False) -> List[int]:
    """Testa as PORTAS_IDENTIFICACAO que ficaram fora do intervalo [inicio, fim]."""
    fora = [p for p in PORTAS_IDENTIFICACAO if not inicio <= p <= fim]
    abertas = []
    em_paralelo(lambda p: porta_aberta(ip, p, timeout_ms), fora, len(fora) or 1, parar,
                lambda p, aberta: abertas.append(p) if aberta else None)
    return sorted(abertas)


def ler_gateway(saida: str) -> Optional[str]:
    """IP do roteador na saida de 'ip -4 route show default' (Linux)
    ou de 'route print -4 0.0.0.0' (Windows)."""
    m = (re.search(r"default via (\d+\.\d+\.\d+\.\d+)", saida)
         or re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", saida, re.M))
    return m.group(1) if m else None


def gateway_padrao() -> Optional[str]:
    """IP do roteador (gateway padrao) desta rede."""
    if WINDOWS:
        saida = _executar(["route", "print", "-4", "0.0.0.0"])
    else:
        saida = _executar(["ip", "-4", "route", "show", "default"])
    return ler_gateway(saida or "")


# Pistas para o palpite do tipo de aparelho, da mais forte para a mais fraca.
_PISTAS_NOME = [
    (("iphone",), "iPhone"),
    (("ipad",), "iPad"),
    (("macbook", "imac", "mac-mini", "macmini"), "Mac"),
    (("appletv", "apple-tv"), "Apple TV"),
    (("android", "galaxy", "redmi", "poco", "moto", "pixel", "xiaomi"), "Celular/tablet Android"),
    (("chromecast", "googletv", "google-tv"), "Chromecast / Google TV"),
    (("echo", "alexa", "firetv", "fire-tv", "kindle"), "Aparelho Amazon (Echo/Fire TV)"),
    (("printer", "epson", "brother", "canon", "laserjet", "deskjet", "officejet"), "Impressora"),
    (("desktop-", "laptop-", "notebook"), "Computador Windows"),
    (("raspberrypi",), "Raspberry Pi"),
    (("esp_", "esp-", "esp32", "esp8266", "tasmota", "shelly", "sonoff"), "Casa inteligente (IoT)"),
    (("tv", "bravia", "roku", "tizen", "webos"), "Smart TV"),
]
def tipo_pelo_modelo(modelo: Optional[str]) -> Optional[str]:
    """Modelos da Apple tem um codigo fixo: 'iPhone14,5', 'iPad13,1', 'MacBookPro18,1',
    'AppleTV11,1', 'AudioAccessory5,1' (HomePod), 'Watch6,1'."""
    m = (modelo or "").lower()
    for prefixo, tipo in (("iphone", "iPhone"), ("ipad", "iPad"), ("ipod", "iPod"),
                          ("macbook", "Mac (notebook)"), ("imac", "Mac"), ("macmini", "Mac"),
                          ("macpro", "Mac"), ("mac", "Mac"), ("appletv", "Apple TV"),
                          ("audioaccessory", "HomePod"), ("watch", "Apple Watch")):
        if m.startswith(prefixo):
            return tipo
    return None


_MARCAS_DE_TV = ("samsung", "lg electronics", "sony", "tcl", "philips", "hisense", "vizio", "roku")
_PISTAS_SERVICOS = [
    ({"_companion-link", "_apple-mobdev2"}, "Aparelho Apple (iPhone, iPad, Mac)"),
    ({"_googlecast"}, "Chromecast / Google TV"),
    ({"_ipp", "_printer", "_pdl-datastream"}, "Impressora"),
    ({"_hap", "_homekit"}, "Casa inteligente (HomeKit)"),
]
_PISTAS_PORTAS = [
    ({62078}, "iPhone/iPad"),
    ({9100, 515, 631}, "Impressora"),
    ({8008, 8009}, "Chromecast / Smart TV"),
    ({3389, 445, 139, 135}, "Computador Windows"),
    ({548}, "Mac"),
    ({7000}, "Aparelho com AirPlay (Apple TV, Mac, caixa de som)"),
    ({554}, "Câmera IP ou Smart TV"),
    ({1883}, "Casa inteligente (IoT)"),
    ({53}, "Roteador / equipamento de rede"),
    ({22}, "Computador Linux / servidor"),
]
_PISTAS_FABRICANTE = [
    (("apple",), "Aparelho Apple (iPhone, iPad, Mac)"),
    (("amazon",), "Aparelho Amazon (Echo/Fire TV/Kindle)"),
    (("google",), "Aparelho Google (Chromecast/Nest)"),
    (("espressif", "tuya", "shelly", "itead", "sonoff"), "Casa inteligente (IoT)"),
    (("raspberry",), "Raspberry Pi"),
    (("sony interactive", "nintendo"), "Videogame"),
    (("hikvision", "dahua", "ezviz"), "Câmera de segurança"),
    (("epson", "canon", "brother", "xerox", "lexmark", "kyocera", "ricoh", "hp inc",
      "hewlett"), "Impressora"),
    (("tp-link", "intelbras", "d-link", "mercusys", "ubiquiti", "mikrotik", "netgear", "tenda",
      "arris", "technicolor", "sagemcom", "askey", "mitrastar", "commscope"),
     "Roteador / equipamento de rede"),
    (("intel", "realtek", "liteon", "lite-on", "azurewave", "hon hai", "cloud network"),
     "Computador / notebook"),
    (("xiaomi", "motorola", "oneplus", "oppo", "vivo mobile", "realme", "huawei device"),
     "Celular (provável)"),
    (("samsung",), "Aparelho Samsung (celular, TV...)"),
    (("lg electronics",), "Aparelho LG (TV, celular...)"),
]


def palpite_tipo(h: Host, gateway: Optional[str] = None) -> str:
    """Palpite de QUE aparelho e, juntando as pistas. Devolve '' se nao der para saber.
    E um palpite: um nome ou uma porta podem enganar.

    A ordem importa: a primeira pista que bater decide. O modelo vem primeiro porque e
    o proprio aparelho dizendo exatamente o que e ('iPhone14,5'); depois o nome e os
    servicos mDNS; o fabricante vem depois das portas porque uma Samsung pode ser
    celular ou TV, mas a porta 8009 aberta indica que tem Chromecast."""
    if h.este_pc:
        return "Este computador"
    if gateway and h.ip == gateway:
        return "Roteador (gateway da rede)"
    pelo_modelo = tipo_pelo_modelo(h.modelo)
    if pelo_modelo:
        return pelo_modelo
    nome, fab = (h.nome or "").lower(), (h.fabricante or "").lower()
    portas = set(h.portas) | set(h.portas_extras)
    for chaves, tipo in _PISTAS_NOME:
        if any(c in nome for c in chaves):
            return tipo
    for chaves, tipo in _PISTAS_SERVICOS:
        if h.servicos & chaves:
            return tipo
    if h.servicos & {"_airplay", "_raop"}:          # recebe AirPlay: TV de outra marca ou Apple TV
        if any(marca in fab for marca in _MARCAS_DE_TV):
            return "Smart TV (com AirPlay)"
        return "Aparelho com AirPlay (Apple TV, caixa de som)"
    for chaves, tipo in _PISTAS_PORTAS:
        if portas & chaves:
            return tipo
    for chaves, tipo in _PISTAS_FABRICANTE:
        if any(c in fab for c in chaves):
            return tipo
    if "_spotify-connect" in h.servicos:
        return "Caixa de som / assistente de voz"
    if mac_aleatorio(h.mac):
        return "Celular ou notebook (MAC privado)"
    if h.ttl:                         # TTL inicial: 64 Linux/Android/Apple, 128 Windows, 255 rede
        if h.ttl > 128:
            return "Equipamento de rede"
        if h.ttl > 64:
            return "Computador Windows"
        return "Linux, Android ou Apple"
    return ""


# --------------------------------------------------------------------------
# Teste rapido pelo terminal:  python scanner.py 192.168.15.0/24 [timeout_ms]
# --------------------------------------------------------------------------
# Este bloco só roda quando o arquivo é executado direto (python scanner.py).
# Quando o app.py faz "import scanner", ele NÃO roda.
if __name__ == "__main__":
    # Passo 1: escolhe a rede (a do argumento ou a sugerida) e o timeout (padrão 500 ms).
    sugeridas = redes_sugeridas()
    if len(sys.argv) < 2 and not sugeridas:
        sys.exit("Nao achei a rede local. Uso: python scanner.py 192.168.0.0/24 [timeout_ms]")
    rede = ler_rede(sys.argv[1] if len(sys.argv) > 1 else sugeridas[0])
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    print("Varrendo %s (timeout %d ms)..." % (rede, timeout))
    # Passo 2: varre (ping + ARP) e mede o tempo. A função de aviso não faz nada aqui.
    t0 = time.time()
    hosts = varrer_rede(rede, timeout, lambda ip, h: None)
    print("Pronto em %.1f s. %d dispositivo(s):" % (time.time() - t0, len(hosts)))
    gateway = gateway_padrao()
    servicos = descobrir_servicos_mdns()
    for h in hosts:
        h.portas = escanear_portas(h.ip, 1, 1024, 300)
        h.portas_extras = escanear_portas_identificacao(h.ip, 1, 1024, 300)
        if not h.este_pc:
            h.nome = descobrir_nome(h.ip)
            if h.ip in servicos:
                aplicar_mdns(h, servicos[h.ip])
        print("  %-15s %-17s %-4s %6s  portas: %s" % (
            h.ip, h.mac or "?", h.metodo, texto_tempo(h.tempo_ms),
            ", ".join(nome_porta(p) for p in h.portas) or "nenhuma", extra))
        print("  %15s fabricante: %s | TTL: %s %s" % (
            "", fabricante(h.mac) or "-", h.ttl or "-", palpite_sistema(h.ttl)))
