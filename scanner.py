"""
NetProbe - parte de REDE (sem interface).

Aqui ficam as 4 tecnicas de rede do trabalho:
  1. fazer_ping()       -> Varredura ICMP (ping sweep)
  2. sondar_arp()       -> Sondagem ARP para quem nao respondeu ao ping
  3. verificar_ip()     -> junta 1 + 2 e monta o par IP/MAC
  4. escanear_portas()  -> lista as portas TCP abertas de um IP

Funciona no Windows e usa so bibliotecas que ja vem com o Python.
Pode ser testado sem a interface:  python scanner.py 192.168.15.0/24
"""
import ctypes
import ipaddress
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional

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
    tempo_ms: Optional[int]     # tempo de resposta do ping (None se veio do ARP)
    este_pc: bool = False       # True se for o proprio computador que esta varrendo
    portas: List[int] = field(default_factory=list)


# --------------------------------------------------------------------------
# Descobrir a rede local
# --------------------------------------------------------------------------
def ips_locais() -> List[str]:
    """IPs IPv4 deste computador (Wi-Fi, cabo, VPN...)."""
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    return ips


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
def fazer_ping(ip: str, timeout_ms: int) -> Optional[int]:
    """Manda 1 ping. Devolve o tempo de resposta em ms, ou None se nao respondeu.

    Usa o comando 'ping' do Windows:  -n 1 = um pacote,  -w = timeout em ms.
    Conferimos se a resposta tem 'TTL=' porque o Windows tambem imprime
    'Host de destino inacessivel' (sem TTL) quando ninguem responde."""
    try:
        r = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True, timeout=timeout_ms / 1000 + 3, creationflags=SEM_JANELA,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    saida = r.stdout.decode("cp850", errors="ignore")
    if "TTL=" not in saida.upper():
        return None
    m = re.search(r"[=<](\d+)\s*ms", saida)   # "tempo=4ms" ou "tempo<1ms"
    return int(m.group(1)) if m else 0


# --------------------------------------------------------------------------
# 2. ARP (Address Resolution Protocol)
# --------------------------------------------------------------------------
# SendARP e uma funcao do proprio Windows (biblioteca iphlpapi.dll).
# Ela manda um pacote "ARP Request" perguntando para a rede inteira:
#   "Quem tem o IP X? Me diga seu MAC."
# Se o dispositivo existe, ele PRECISA responder (senao nao conseguiria usar a rede),
# mesmo que o firewall dele bloqueie ping. E isso que descobre quem "se esconde".
try:
    _iphlpapi = ctypes.windll.iphlpapi
    _iphlpapi.SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                  ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    _iphlpapi.SendARP.restype = ctypes.c_ulong
except AttributeError:  # nao e Windows
    _iphlpapi = None


def sondar_arp(ip: str, tentativas: int = 2) -> Optional[str]:
    """Manda um ARP Request para o IP. Devolve o MAC (ex.: 'A4-5E-60-12-34-56') ou None.
    Tenta 2 vezes: celulares em modo economia as vezes demoram a responder."""
    if _iphlpapi is None:
        return None
    destino = struct.unpack("=I", socket.inet_aton(ip))[0]   # IP no formato que o Windows espera
    for _ in range(tentativas):
        mac = (ctypes.c_ubyte * 6)()                         # espaco para os 6 bytes do MAC
        tamanho = ctypes.c_ulong(6)
        resultado = _iphlpapi.SendARP(destino, 0, ctypes.byref(mac), ctypes.byref(tamanho))
        bytes_mac = bytes(mac[: tamanho.value])
        if resultado == 0 and tamanho.value == 6 and bytes_mac != b"\x00" * 6:   # 0 = sucesso
            return "-".join("%02X" % b for b in bytes_mac)
    return None


def mac_da_tabela_arp(ip: str) -> Optional[str]:
    """Plano B: le a tabela ARP do Windows ('arp -a'), onde ficam guardados
    os MACs que o computador ja descobriu recentemente."""
    try:
        saida = subprocess.run(["arp", "-a", ip], capture_output=True,
                               creationflags=SEM_JANELA).stdout.decode("cp850", errors="ignore")
    except OSError:
        return None
    m = re.search(r"\b" + re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", saida, re.I)
    if m and m.group(1).lower() not in ("ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"):
        return m.group(1).upper()
    return None


def mac_deste_pc(ip: str) -> Optional[str]:
    """O ARP nao funciona para o proprio IP, entao lemos o MAC no 'ipconfig /all'."""
    try:
        saida = subprocess.run(["ipconfig", "/all"], capture_output=True,
                               creationflags=SEM_JANELA).stdout.decode("cp850", errors="ignore")
    except OSError:
        return None
    for bloco in re.split(r"\r?\n(?=\S)", saida):            # um bloco por placa de rede
        if re.search(r"\b" + re.escape(ip) + r"\b", bloco):
            m = re.search(r"([0-9A-F]{2}(?:-[0-9A-F]{2}){5})", bloco, re.I)
            if m:
                return m.group(1).upper()
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
        # Ja sabemos que existe: tenta o ARP 2 vezes e, se falhar, olha a tabela ARP
        return Host(ip, sondar_arp(ip, tentativas=2) or mac_da_tabela_arp(ip), "PING", tempo)

    mac = sondar_arp(ip, tentativas=2)   # 2 tentativas: aparelhos dormindo demoram a responder
    if mac is not None:
        return Host(ip, mac, "ARP", None)
    return None


def varrer_rede(rede: ipaddress.IPv4Network, timeout_ms: int,
                ao_verificar: Callable[[str, Optional[Host]], None],
                parar: Callable[[], bool] = lambda: False,
                threads: int = 256) -> List[Host]:
    """Verifica todos os IPs da rede AO MESMO TEMPO (varias threads).

    Sem threads, 254 IPs x (timeout do ping + ~8 s de ARP) = mais de 30 minutos.
    Com 256 threads, os 254 IPs de uma rede /24 sao testados todos juntos.
    'ao_verificar(ip, host)' e chamado a cada IP terminado (para a tela atualizar na hora)."""
    meus_ips = ips_locais()
    encontrados = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        tarefas = {pool.submit(verificar_ip, str(ip), timeout_ms, meus_ips): str(ip)
                   for ip in rede.hosts()}
        for tarefa in as_completed(tarefas):
            if parar():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            host = tarefa.result()
            if host:
                encontrados.append(host)
            ao_verificar(tarefas[tarefa], host)
    encontrados.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return encontrados


# --------------------------------------------------------------------------
# 4. Portas abertas (TCP connect scan)
# --------------------------------------------------------------------------
def porta_aberta(ip: str, porta: int, timeout_ms: int) -> bool:
    """Tenta abrir uma conexao TCP (o 'aperto de mao' de 3 vias: SYN, SYN-ACK, ACK).
    Se conectar, tem um programa escutando ali: a porta esta ABERTA."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout_ms / 1000)
        return s.connect_ex((ip, porta)) == 0   # 0 = conectou


def escanear_portas(ip: str, inicio: int, fim: int, timeout_ms: int,
                    parar: Callable[[], bool] = lambda: False, threads: int = 200) -> List[int]:
    """Testa as portas de 'inicio' ate 'fim' (inclusive), varias ao mesmo tempo."""
    abertas = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        tarefas = {pool.submit(porta_aberta, ip, p, timeout_ms): p for p in range(inicio, fim + 1)}
        for tarefa in as_completed(tarefas):
            if parar():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            if tarefa.result():
                abertas.append(tarefas[tarefa])
    return sorted(abertas)


def nome_porta(p: int) -> str:
    """'80' -> '80 (HTTP)'."""
    nome = SERVICOS.get(p)
    return "%d (%s)" % (p, nome) if nome else str(p)


# --------------------------------------------------------------------------
# Teste rapido pelo terminal:  python scanner.py 192.168.15.0/24 [timeout_ms]
# --------------------------------------------------------------------------
if __name__ == "__main__":
    rede = ler_rede(sys.argv[1] if len(sys.argv) > 1 else redes_sugeridas()[0])
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    print("Varrendo %s (timeout %d ms)..." % (rede, timeout))
    t0 = time.time()
    hosts = varrer_rede(rede, timeout, lambda ip, h: None)
    print("Pronto em %.1f s. %d dispositivo(s):" % (time.time() - t0, len(hosts)))
    for h in hosts:
        h.portas = escanear_portas(h.ip, 1, 1024, 300)
        extra = " (este PC)" if h.este_pc else ""
        print("  %-15s %-17s %-4s %5s  portas: %s%s" % (
            h.ip, h.mac or "?", h.metodo, "%dms" % h.tempo_ms if h.tempo_ms is not None else "-",
            ", ".join(nome_porta(p) for p in h.portas) or "nenhuma", extra))
