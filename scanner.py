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
import ctypes
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

WINDOWS = sys.platform.startswith("win")

# Evita que cada "ping" abra uma janela preta de terminal no Windows
SEM_JANELA = 0x08000000  # CREATE_NO_WINDOW

# Nomes conhecidos de algumas portas, so para exibir na tela
SERVICOS = {
    20: "FTP-dados", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "Impressora", 1900: "UPnP",
    3306: "MySQL", 3389: "Área Remota", 5000: "UPnP/Flask", 5357: "WSD",
    7000: "AirPlay", 8008: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9100: "Impressora", 62078: "iPhone-sync",
}


@dataclass
class Host:
    """Um dispositivo encontrado na rede."""
    ip: str
    mac: Optional[str]          # endereco fisico, ex.: A4-5E-60-12-34-56
    metodo: str                 # "PING" (respondeu ao ping) ou "ARP" (bloqueia ping)
    tempo_ms: Optional[float]   # tempo de resposta do ping (None se veio do ARP)
    este_pc: bool = False       # True se for o proprio computador que esta varrendo
    portas: List[int] = field(default_factory=list)


# --------------------------------------------------------------------------
# Utilitarios
# --------------------------------------------------------------------------
def _executar(comando: List[str], timeout: float = 10) -> Optional[str]:
    """Roda um comando do sistema e devolve o que ele imprimiu (ou None se falhar).
    No Windows esconde a janela do terminal; no Linux forca mensagens em ingles
    (LC_ALL=C) para o texto ser sempre o mesmo, qualquer que seja o idioma do sistema."""
    extra = {}
    if WINDOWS:
        extra["creationflags"] = SEM_JANELA
    else:
        extra["env"] = dict(os.environ, LC_ALL="C")
    try:
        r = subprocess.run(comando, capture_output=True, timeout=timeout, **extra)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return r.stdout.decode("cp850" if WINDOWS else "utf-8", errors="ignore")


def normalizar_mac(texto: Optional[str]) -> Optional[str]:
    """'a4:5e:60:12:34:56' ou 'a4-5e-...' -> 'A4-5E-60-12-34-56'.
    Devolve None para MACs que nao sao de um aparelho (tudo 0 ou broadcast)."""
    if not texto:
        return None
    partes = re.split(r"[:-]", texto.strip())
    if len(partes) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in partes):
        return None
    mac = "-".join(p.zfill(2).upper() for p in partes)
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
    pool = ThreadPoolExecutor(max_workers=threads)
    pendentes = {pool.submit(funcao, item): item for item in itens}
    parado = False
    try:
        while pendentes and not parado:
            prontos, _ = wait(pendentes, timeout=0.2, return_when=FIRST_COMPLETED)
            for tarefa in prontos:
                if parar():
                    break
                ao_terminar(pendentes.pop(tarefa), tarefa.result())
            parado = parar()
    finally:
        pool.shutdown(wait=not parado, cancel_futures=True)
    return parado


def mac_aleatorio(mac: Optional[str]) -> bool:
    """True se o MAC e "administrado localmente" (bit 0x02 do 1o byte ligado).
    Celulares modernos (Android/iPhone) usam MAC aleatorio por rede, por privacidade."""
    if not mac:
        return False
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Descobrir a rede local
# --------------------------------------------------------------------------
def ips_locais() -> List[str]:
    """IPs IPv4 deste computador (Wi-Fi, cabo, VPN...)."""
    ips = []
    # Truque: "conectar" um socket UDP nao envia nenhum pacote, mas faz o sistema
    # escolher a placa de rede da rota padrao, e assim descobrimos o IP principal.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ips.append(s.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.append(info[4][0])
    except OSError:
        pass
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
        rede = str(ipaddress.ip_network(ip + "/24", strict=False))
        if rede not in redes:
            redes.append(rede)
    redes.sort(key=lambda r: not ipaddress.ip_network(r).is_private)
    return redes


def ler_rede(texto: str) -> ipaddress.IPv4Network:
    """Converte '192.168.15.0/24' (ou so '192.168.15.0') num objeto de rede.
    Gera ValueError com mensagem clara se estiver errado."""
    texto = texto.strip()
    if "/" not in texto:
        texto += "/24"
    try:
        rede = ipaddress.IPv4Network(texto, strict=False)
    except ValueError:
        raise ValueError("Rede inválida. Use o formato 192.168.0.0/24")
    if rede.num_addresses > 1024:
        raise ValueError("Rede grande demais. Use /22 ou menor (até 1024 IPs), ex.: /24")
    return rede


# --------------------------------------------------------------------------
# 1. PING (ICMP Echo Request / Echo Reply)
# --------------------------------------------------------------------------
def interpretar_ping(saida: Optional[str]) -> Optional[float]:
    """Le a saida do comando ping e devolve o tempo em ms, ou None se nao houve resposta.

    So conta como resposta se tiver 'TTL=', porque o ping tambem imprime
    'Host de destino inacessivel' / 'Destination Host Unreachable' (sem TTL)
    quando ninguem responde. Formatos aceitos:
      Windows:  'Resposta de 192.168.0.1: bytes=32 tempo=4ms TTL=64'   (ou 'tempo<1ms')
      Linux:    '64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=2.87 ms'"""
    if not saida or "TTL=" not in saida.upper():
        return None
    m = re.search(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", saida)
    return float(m.group(1).replace(",", ".")) if m else 0.0


def fazer_ping(ip: str, timeout_ms: int) -> Optional[float]:
    """Manda 1 ping. Devolve o tempo de resposta em ms, ou None se nao respondeu.

    Windows:  ping -n 1 -w <ms>  (um pacote, timeout em milissegundos)
    Linux:    ping -c 1 -W <s>   (um pacote, timeout em segundos, aceita fracao)"""
    if WINDOWS:
        comando = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        comando = ["ping", "-c", "1", "-n", "-W", "%.3f" % (timeout_ms / 1000), ip]
    return interpretar_ping(_executar(comando, timeout=timeout_ms / 1000 + 3))


# --------------------------------------------------------------------------
# 2. ARP (Address Resolution Protocol)
# --------------------------------------------------------------------------
# A ideia: um ARP Request pergunta para a rede inteira "Quem tem o IP X? Me diga seu MAC."
# Se o dispositivo existe, ele PRECISA responder (senao nao conseguiria usar a rede),
# mesmo que o firewall dele bloqueie ping. E isso que descobre quem "se esconde".
#
# WINDOWS: SendARP e uma funcao do proprio Windows (iphlpapi.dll) que manda o ARP
#          e devolve o MAC. Nao precisa de administrador.
# LINUX:   sem root nao da para montar o pacote ARP na mao. Entao mandamos um
#          datagrama UDP qualquer para o IP: para entrega-lo, o kernel PRECISA
#          descobrir o MAC e envia ele mesmo o ARP Request. Depois lemos o
#          resultado na tabela de vizinhos (ip neigh): REACHABLE = respondeu,
#          FAILED = ninguem respondeu.
try:
    _iphlpapi = ctypes.windll.iphlpapi
    _iphlpapi.SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                  ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    _iphlpapi.SendARP.restype = ctypes.c_ulong
except AttributeError:  # nao e Windows
    _iphlpapi = None


def _sondar_arp_windows(ip: str, tentativas: int) -> Optional[str]:
    if _iphlpapi is None:
        return None
    destino = struct.unpack("=I", socket.inet_aton(ip))[0]   # IP no formato que o Windows espera
    for _ in range(tentativas):
        mac = (ctypes.c_ubyte * 6)()                         # espaco para os 6 bytes do MAC
        tamanho = ctypes.c_ulong(6)
        resultado = _iphlpapi.SendARP(destino, 0, ctypes.byref(mac), ctypes.byref(tamanho))
        if resultado == 0 and tamanho.value == 6:            # 0 = sucesso
            achado = normalizar_mac("-".join("%02X" % b for b in mac[:6]))
            if achado:
                return achado
    return None


def ler_vizinhos_linux(saida: str) -> Dict[str, Tuple[Optional[str], str]]:
    """Interpreta 'ip -4 neigh show'. Devolve {ip: (mac ou None, estado)}. Exemplos de linha:
      192.168.1.1 dev wlp3s0 lladdr f4:e8:4f:98:1b:94 REACHABLE
      192.168.1.9 dev wlp3s0 lladdr 3c:22:fb:00:11:22 router STALE
      192.168.1.50 dev wlp3s0 FAILED"""
    tabela = {}
    for linha in saida.splitlines():
        partes = linha.split()
        if len(partes) < 2:
            continue
        mac = None
        if "lladdr" in partes:
            i = partes.index("lladdr")
            if i + 1 < len(partes):
                mac = normalizar_mac(partes[i + 1])
        tabela[partes[0]] = (mac, partes[-1].upper())
    return tabela


_vizinhos_trava = threading.Lock()
_vizinhos_cache: Tuple[float, Dict[str, Tuple[Optional[str], str]]] = (0.0, {})


def vizinhos_linux(max_idade: float = 0.25) -> Dict[str, Tuple[Optional[str], str]]:
    """Tabela de vizinhos (cache ARP) do Linux. Como ate 256 threads consultam a tabela
    ao mesmo tempo, ela e lida no maximo a cada 0,25 s e compartilhada entre todas."""
    global _vizinhos_cache
    with _vizinhos_trava:
        lida_em, tabela = _vizinhos_cache
        if time.monotonic() - lida_em > max_idade:
            saida = _executar(["ip", "-4", "neigh", "show"], timeout=5)
            tabela = ler_vizinhos_linux(saida or "")
            _vizinhos_cache = (time.monotonic(), tabela)
        return tabela


def _provocar_arp(ip: str):
    """Manda 1 datagrama UDP para a porta 9 ('discard'). O conteudo nao importa:
    o objetivo e obrigar o kernel a enviar um ARP Request para esse IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"NetProbe", (ip, 9))
    except OSError:
        pass


def _sondar_arp_linux(ip: str, tentativas: int) -> Optional[str]:
    # Cada tentativa: o kernel manda 3 ARP Requests (1 por segundo). Se o IP ja estava
    # na tabela como STALE (visto ha algum tempo), o kernel espera ~5 s antes de
    # reconfirmar, por isso o limite de 9 s.
    for _ in range(tentativas):
        inicio = time.monotonic()
        _provocar_arp(ip)
        while time.monotonic() - inicio < 9:
            time.sleep(0.25)
            mac, estado = vizinhos_linux().get(ip, (None, ""))
            passou = time.monotonic() - inicio
            if estado in ("REACHABLE", "PERMANENT") and mac:
                return mac                                    # respondeu ao ARP
            if not estado and passou > 1.5:
                return None                                   # fora da rede local: nao ha ARP
            if estado == "FAILED" and passou > 1.0:
                break                                         # ninguem respondeu
    return None


def sondar_arp(ip: str, tentativas: int = 2) -> Optional[str]:
    """Manda um ARP Request para o IP. Devolve o MAC (ex.: 'A4-5E-60-12-34-56') ou None.
    Tenta 2 vezes: celulares em modo economia as vezes demoram a responder."""
    if WINDOWS:
        return _sondar_arp_windows(ip, tentativas)
    return _sondar_arp_linux(ip, tentativas)


def ler_arp_windows(saida: str, ip: str) -> Optional[str]:
    """Procura o MAC do IP na saida do 'arp -a' do Windows. Exemplo de linha:
      192.168.15.1          a4-5e-60-12-34-56     dinâmico"""
    m = re.search(r"(?<![\d.])" + re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", saida, re.I)
    return normalizar_mac(m.group(1)) if m else None


def mac_da_tabela_arp(ip: str) -> Optional[str]:
    """Le a tabela ARP do sistema, onde ficam guardados os MACs que o
    computador ja descobriu recentemente (por exemplo, durante o ping)."""
    if WINDOWS:
        saida = _executar(["arp", "-a", ip])
        return ler_arp_windows(saida, ip) if saida else None
    mac, estado = vizinhos_linux().get(ip, (None, ""))
    return mac if estado not in ("FAILED", "INCOMPLETE") else None


def mac_deste_pc(ip: str) -> Optional[str]:
    """O ARP nao funciona para o proprio IP, entao perguntamos ao sistema qual e o MAC
    da placa de rede que tem esse IP (Windows: 'ipconfig /all'; Linux: 'ip addr')."""
    if WINDOWS:
        saida = _executar(["ipconfig", "/all"]) or ""
        for bloco in re.split(r"\r?\n(?=\S)", saida):        # um bloco por placa de rede
            if re.search(r"(?<![\d.])" + re.escape(ip) + r"(?![\d])", bloco):
                m = re.search(r"([0-9A-F]{2}(?:-[0-9A-F]{2}){5})", bloco, re.I)
                if m:
                    return normalizar_mac(m.group(1))
        return None
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
    if ip in meus_ips:
        return Host(ip, mac_deste_pc(ip), "PING", 0, este_pc=True)

    tempo = fazer_ping(ip, timeout_ms)
    if tempo is not None:
        # Ja sabemos que existe. O ping ja fez o ARP, entao o MAC esta no cache.
        if WINDOWS:
            mac = sondar_arp(ip, tentativas=2) or mac_da_tabela_arp(ip)
        else:
            mac = mac_da_tabela_arp(ip) or sondar_arp(ip, tentativas=1)
        return Host(ip, mac, "PING", tempo)

    mac = sondar_arp(ip, tentativas=2)   # 2 tentativas: aparelhos dormindo demoram a responder
    if mac is not None:
        return Host(ip, mac, "ARP", None)
    return None


def varrer_rede(rede: ipaddress.IPv4Network, timeout_ms: int,
                ao_verificar: Callable[[str, Optional[Host]], None],
                parar: Callable[[], bool] = lambda: False,
                threads: int = 256) -> List[Host]:
    """Verifica todos os IPs da rede AO MESMO TEMPO (varias threads).

    Sem threads, 254 IPs x (timeout do ping + ~6 s de ARP) = mais de 25 minutos.
    Com 256 threads, os 254 IPs de uma rede /24 sao testados todos juntos.
    'ao_verificar(ip, host)' e chamado a cada IP terminado (para a tela atualizar na hora)."""
    meus_ips = ips_locais()
    encontrados = []

    def terminou(ip, host):
        if host:
            encontrados.append(host)
        ao_verificar(ip, host)

    em_paralelo(lambda ip: verificar_ip(ip, timeout_ms, meus_ips),
                [str(ip) for ip in rede.hosts()], threads, parar, terminou)
    encontrados.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return encontrados


# --------------------------------------------------------------------------
# 4. Portas abertas (TCP connect scan)
# --------------------------------------------------------------------------
def porta_aberta(ip: str, porta: int, timeout_ms: int) -> bool:
    """Tenta abrir uma conexao TCP (o 'aperto de mao' de 3 vias: SYN, SYN-ACK, ACK).
    Se conectar, tem um programa escutando ali: a porta esta ABERTA."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_ms / 1000)
            return s.connect_ex((ip, porta)) == 0   # 0 = conectou
    except OSError:          # ex.: rede caiu no meio; conta como fechada
        return False


def escanear_portas(ip: str, inicio: int, fim: int, timeout_ms: int,
                    parar: Callable[[], bool] = lambda: False, threads: int = 200) -> List[int]:
    """Testa as portas de 'inicio' ate 'fim' (inclusive), varias ao mesmo tempo."""
    abertas = []
    em_paralelo(lambda p: porta_aberta(ip, p, timeout_ms), range(inicio, fim + 1), threads, parar,
                lambda p, aberta: abertas.append(p) if aberta else None)
    return sorted(abertas)


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
# Teste rapido pelo terminal:  python scanner.py 192.168.15.0/24 [timeout_ms]
# --------------------------------------------------------------------------
if __name__ == "__main__":
    sugeridas = redes_sugeridas()
    if len(sys.argv) < 2 and not sugeridas:
        sys.exit("Nao achei a rede local. Uso: python scanner.py 192.168.0.0/24 [timeout_ms]")
    rede = ler_rede(sys.argv[1] if len(sys.argv) > 1 else sugeridas[0])
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    print("Varrendo %s (timeout %d ms)..." % (rede, timeout))
    t0 = time.time()
    hosts = varrer_rede(rede, timeout, lambda ip, h: None)
    print("Pronto em %.1f s. %d dispositivo(s):" % (time.time() - t0, len(hosts)))
    for h in hosts:
        h.portas = escanear_portas(h.ip, 1, 1024, 300)
        extra = " (este PC)" if h.este_pc else ""
        print("  %-15s %-17s %-4s %6s  portas: %s%s" % (
            h.ip, h.mac or "?", h.metodo, texto_tempo(h.tempo_ms),
            ", ".join(nome_porta(p) for p in h.portas) or "nenhuma", extra))
