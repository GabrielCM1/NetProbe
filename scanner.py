"""
NetProbe - parte de REDE (sem interface).

Aqui ficam as 4 tecnicas de rede do trabalho:
  1. fazer_ping()       -> Varredura ICMP (ping sweep)
  2. sondar_arp()       -> Sondagem ARP para quem nao respondeu ao ping
  3. verificar_ip()     -> junta 1 + 2 e monta o par IP/MAC
  4. escanear_portas()  -> lista as portas TCP abertas de um IP

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
#                                       nada?      ------------------> None (IP vazio)
#
#   Depois, para cada Host online (o app.py chama):
#     escanear_portas(ip, inicio, fim)
#       └─ em_paralelo(...)                <- roda porta_aberta() em 200 threads
#            └─ porta_aberta(ip, porta)    <- tenta o handshake TCP
#
#   E para mostrar na tela (o app.py chama):
#     fabricante(mac)        <- procura os 3 primeiros bytes do MAC na lista do IEEE
#     palpite_sistema(ttl)   <- 64 / 128 / 255 -> Linux / Windows / rede
#
# Ordem das seções neste arquivo:
#   Imports e constantes -> classe Host -> utilitários -> descobrir a rede
#   -> 1. PING -> 2. ARP -> 3. verificar/varrer -> 4. portas -> fabricante
#   -> teste pelo terminal
# ==========================================================================

# --- Bibliotecas usadas (todas já vêm com o Python, nada para instalar) ---
import ctypes                  # chamar funções do Windows escritas em C (SendARP)
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
from typing import Callable, Dict, List, Optional, Tuple   # só anotações de tipo (não mudam nada)

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
    443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "Impressora", 1900: "UPnP",
    3306: "MySQL", 3389: "Área Remota", 5000: "UPnP/Flask", 5357: "WSD",
    7000: "AirPlay", 8008: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9100: "Impressora", 62078: "iPhone-sync",
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
    este_pc: bool = False       # True se for o próprio computador que está varrendo
    portas: List[int] = field(default_factory=list)   # preenchido depois, no passo das portas
    ttl: Optional[int] = None   # TTL da resposta do ping (dá uma pista do sistema operacional)


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

    O pedido de parar e conferido a cada 0,2 s (e nao so quando algum item termina):
    na fase do ARP, centenas de IPs ficam varios segundos sem terminar.
    Ao parar, nao espera os itens que ainda estao rodando. Devolve True se foi parado."""
    # É o "motor" de paralelismo do projeto. Usado duas vezes:
    #   - varrer_rede():     funcao = verificar_ip,  itens = os 254 IPs,   256 threads
    #   - escanear_portas(): funcao = porta_aberta,  itens = as portas,    200 threads
    #
    # Passo 1: cria o pool (um grupo fixo de "trabalhadores").
    pool = ThreadPoolExecutor(max_workers=threads)
    # Passo 2: entrega TODOS os itens de uma vez. submit() não espera: só coloca na fila
    # do pool e devolve uma "tarefa" (Future), que vai ter o resultado quando terminar.
    # O dicionário lembra qual item é de qual tarefa: {tarefa: item}.
    pendentes = {pool.submit(funcao, item): item for item in itens}
    parado = False
    try:
        # Passo 3: enquanto houver tarefas pendentes e ninguém clicou em Parar...
        while pendentes and not parado:
            # Espera até alguma tarefa terminar, mas NO MÁXIMO 0,2 s.
            # Esse limite é o que faz o botão Parar responder rápido.
            prontos, _ = wait(pendentes, timeout=0.2, return_when=FIRST_COMPLETED)
            # Passo 4: para cada tarefa que terminou, tira da lista de pendentes
            # e avisa quem chamou (ao_terminar), com o item e o resultado.
            for tarefa in prontos:
                if parar():
                    break
                ao_terminar(pendentes.pop(tarefa), tarefa.result())
            # Passo 5: confere de novo se pediram para parar.
            parado = parar()
    finally:
        # Passo 6: desliga o pool. Se terminou normal, espera todo mundo (wait=True).
        # Se foi parado, não espera e cancela o que ainda nem começou.
        pool.shutdown(wait=not parado, cancel_futures=True)
    return parado


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
    # Passo 3: tira repetidos, mantendo a ordem (o principal fica primeiro),
    # e descarta 127.x.x.x (o próprio PC por dentro) e 0.x.x.x (inválido).
    unicos = []
    for ip in ips:
        if ip not in unicos and not ip.startswith(("127.", "0.")):
            unicos.append(ip)
    return unicos


def redes_sugeridas() -> List[str]:
    """Transforma cada IP local numa rede /24, colocando as redes de casa
    (192.168.x.x, 10.x.x.x, 172.16-31.x.x) primeiro. Ex.: 192.168.15.6 -> 192.168.15.0/24"""
    redes = []
    for ip in ips_locais():
        # strict=False aceita um IP de aparelho e devolve a rede dele:
        # "192.168.15.6/24" -> rede 192.168.15.0/24
        rede = str(ipaddress.ip_network(ip + "/24", strict=False))
        if rede not in redes:
            redes.append(rede)
    # Ordena: redes privadas (de casa) primeiro. Isso evita sugerir uma VPN,
    # como a Radmin (26.x.x.x), que não é uma faixa privada.
    # A chave é "not privada": False (privada) vem antes de True.
    redes.sort(key=lambda r: not ipaddress.ip_network(r).is_private)
    return redes


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
    ao mesmo tempo, ela e lida no maximo a cada 0,25 s e compartilhada entre todas."""
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
        return Host(ip, mac_deste_pc(ip), "PING", 0, este_pc=True)

    # Passo 2: tenta o PING (elemento 1).
    resposta = fazer_ping(ip, timeout_ms)
    if resposta is not None:
        tempo, ttl = resposta
        # Já sabemos que existe. O ping já fez o ARP, então o MAC está no cache.
        # Passo 2b: pega o MAC (elemento 3). A ordem muda por sistema só por rapidez:
        # no Windows a SendARP é direta; no Linux a tabela de vizinhos já está lida.
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


# --------------------------------------------------------------------------
# Fabricante pelo MAC
# --------------------------------------------------------------------------
# Os 3 primeiros bytes do MAC (o "OUI") são comprados pelo fabricante e registrados
# publicamente pelo IEEE. Ex.: F4-E8-4F-... = ZTE. A lista fica em fabricantes.txt
# (cópia do registro do IEEE mantida pelo Wireshark). O programa não acessa a internet.
ARQUIVO_FABRICANTES = Path(__file__).resolve().parent / "fabricantes.txt"   # na pasta do projeto
_fabricantes: Optional[Dict[str, str]] = None    # a lista na memória (None = ainda não leu)


def carregar_fabricantes() -> Dict[str, str]:
    """Le o fabricantes.txt so na 1a vez: {'F4E84F': 'ZTE', ...}. Sem o arquivo, fica vazio."""
    global _fabricantes
    # Só lê o arquivo na primeira chamada. Nas outras, devolve o que já está na memória
    # (o arquivo tem quase 59 mil linhas; ler a cada aparelho seria lento).
    if _fabricantes is None:
        tabela = {}
        try:
            with open(ARQUIVO_FABRICANTES, encoding="utf-8") as f:
                for linha in f:
                    # Cada linha: PREFIXO<TAB>FABRICANTE. partition separa no TAB.
                    prefixo, _, nome = linha.rstrip("\n").partition("\t")
                    # Ignora as linhas de comentário (começam com "#").
                    if nome and not linha.startswith("#"):
                        tabela[prefixo] = nome
        except OSError:
            pass                                  # sem o arquivo: tabela vazia, sem erro
        _fabricantes = tabela
    return _fabricantes


def fabricante(mac: Optional[str]) -> Optional[str]:
    """'F4-E8-4F-98-1B-94' -> 'ZTE'. None se nao souber.
    MAC aleatorio nao tem fabricante: foi inventado pelo aparelho, por privacidade."""
    # Passo 1: MAC vazio ou aleatório não tem fabricante.
    if not mac or mac_aleatorio(mac):
        return None
    # Passo 2: tira os traços: "F4-E8-4F-98-1B-94" -> "F4E84F981B94".
    hexa = mac.replace("-", "")
    tabela = carregar_fabricantes()
    # O IEEE também vende blocos menores (prefixos de 7 e 9 dígitos) dentro de um OUI,
    # então o prefixo mais longo é procurado primeiro.
    # Passo 3: tenta os 9 primeiros dígitos, depois 7, depois 6 (o OUI comum).
    for tamanho in (9, 7, 6):
        nome = tabela.get(hexa[:tamanho])
        if nome:
            return nome
    return None


def texto_tempo(tempo_ms: Optional[float]) -> str:
    """2.87 -> '3 ms';  0.4 -> '<1 ms';  None -> '-'."""
    if tempo_ms is None:
        return "-"
    return "<1 ms" if tempo_ms < 1 else "%d ms" % round(tempo_ms)


# --------------------------------------------------------------------------
# Teste rápido pelo terminal:  python scanner.py 192.168.15.0/24 [timeout_ms]
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
    # Passo 3: para cada aparelho, testa as portas 1 a 1024 e imprime tudo.
    for h in hosts:
        h.portas = escanear_portas(h.ip, 1, 1024, 300)
        extra = " (este PC)" if h.este_pc else ""
        print("  %-15s %-17s %-4s %6s  portas: %s%s" % (
            h.ip, h.mac or "?", h.metodo, texto_tempo(h.tempo_ms),
            ", ".join(nome_porta(p) for p in h.portas) or "nenhuma", extra))
        print("  %15s fabricante: %s | TTL: %s %s" % (
            "", fabricante(h.mac) or "-", h.ttl or "-", palpite_sistema(h.ttl)))
