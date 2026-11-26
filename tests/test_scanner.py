"""Testes da parte de rede (scanner.py).

Rodar (na pasta do projeto):  python -m unittest discover -s tests -v

Os testes de interpretacao usam saidas reais dos comandos (Windows em portugues
e ingles, Linux), entao funcionam em qualquer sistema, sem rede.
"""
import ipaddress
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scanner  # noqa: E402


class TestInterpretarPing(unittest.TestCase):
    def test_windows_portugues(self):
        saida = ("Disparando 192.168.15.1 com 32 bytes de dados:\r\n"
                 "Resposta de 192.168.15.1: bytes=32 tempo=4ms TTL=64\r\n")
        self.assertEqual(scanner.interpretar_ping(saida), 4)

    def test_windows_menor_que_1ms(self):
        saida = "Reply from 192.168.15.1: bytes=32 time<1ms TTL=128\r\n"
        self.assertEqual(scanner.interpretar_ping(saida), 1)

    def test_windows_host_inacessivel_nao_conta(self):
        # O Windows imprime "Resposta de" mesmo quando NINGUEM respondeu
        saida = "Resposta de 192.168.15.6: Host de destino inacessível.\r\n"
        self.assertIsNone(scanner.interpretar_ping(saida))

    def test_windows_esgotado(self):
        self.assertIsNone(scanner.interpretar_ping("Esgotado o tempo limite do pedido.\r\n"))

    def test_linux_com_decimal(self):
        saida = ("64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.87 ms\n\n"
                 "rtt min/avg/max/mdev = 2.868/2.868/2.868/0.000 ms\n")
        self.assertAlmostEqual(scanner.interpretar_ping(saida), 2.87)

    def test_linux_sem_resposta(self):
        saida = ("From 192.168.1.154 icmp_seq=1 Destination Host Unreachable\n"
                 "1 packets transmitted, 0 received, +1 errors, 100% packet loss\n")
        self.assertIsNone(scanner.interpretar_ping(saida))

    def test_saida_vazia(self):
        self.assertIsNone(scanner.interpretar_ping(None))
        self.assertIsNone(scanner.interpretar_ping(""))


class TestMac(unittest.TestCase):
    def test_normalizar(self):
        self.assertEqual(scanner.normalizar_mac("a4:5e:60:12:34:56"), "A4-5E-60-12-34-56")
        self.assertEqual(scanner.normalizar_mac("a4-5e-60-12-34-56\n"), "A4-5E-60-12-34-56")
        self.assertEqual(scanner.normalizar_mac("0:1:2:3:4:5"), "00-01-02-03-04-05")

    def test_normalizar_rejeita_invalidos(self):
        for ruim in (None, "", "ff-ff-ff-ff-ff-ff", "00:00:00:00:00:00", "a4:5e:60", "zz:zz:zz:zz:zz:zz"):
            self.assertIsNone(scanner.normalizar_mac(ruim), ruim)

    def test_mac_aleatorio(self):
        self.assertTrue(scanner.mac_aleatorio("FE-CB-1F-8C-09-AD"))    # bit 0x02 ligado
        self.assertTrue(scanner.mac_aleatorio("6A-25-C6-23-AF-B0"))
        self.assertFalse(scanner.mac_aleatorio("F4-E8-4F-98-1B-94"))   # MAC de fabrica
        self.assertFalse(scanner.mac_aleatorio(None))


class TestTabelaArp(unittest.TestCase):
    ARP_WINDOWS = (
        "\r\nInterface: 192.168.15.6 --- 0xb\r\n"
        "  Endereço IP           Endereço físico       Tipo\r\n"
        "  192.168.15.1          a4-5e-60-12-34-56     dinâmico\r\n"
        "  192.168.15.10         3c-22-fb-00-11-22     dinâmico\r\n"
        "  192.168.15.255        ff-ff-ff-ff-ff-ff     estático\r\n")

    def test_windows_acha_ip_exato(self):
        self.assertEqual(scanner.ler_arp_windows(self.ARP_WINDOWS, "192.168.15.1"), "A4-5E-60-12-34-56")
        self.assertEqual(scanner.ler_arp_windows(self.ARP_WINDOWS, "192.168.15.10"), "3C-22-FB-00-11-22")

    def test_windows_ignora_broadcast_e_ausente(self):
        self.assertIsNone(scanner.ler_arp_windows(self.ARP_WINDOWS, "192.168.15.255"))
        self.assertIsNone(scanner.ler_arp_windows(self.ARP_WINDOWS, "192.168.15.7"))

    def test_linux_ip_neigh(self):
        saida = ("192.168.1.1 dev wlp3s0 lladdr f4:e8:4f:98:1b:94 REACHABLE\n"
                 "192.168.1.9 dev wlp3s0 lladdr 3c:22:fb:00:11:22 router STALE\n"
                 "192.168.1.50 dev wlp3s0 FAILED\n"
                 "192.168.1.51 dev wlp3s0 INCOMPLETE\n")
        t = scanner.ler_vizinhos_linux(saida)
        self.assertEqual(t["192.168.1.1"], ("F4-E8-4F-98-1B-94", "REACHABLE"))
        self.assertEqual(t["192.168.1.9"], ("3C-22-FB-00-11-22", "STALE"))
        self.assertEqual(t["192.168.1.50"], (None, "FAILED"))
        self.assertEqual(t["192.168.1.51"], (None, "INCOMPLETE"))


class TestLerRede(unittest.TestCase):
    def test_formatos_validos(self):
        self.assertEqual(scanner.ler_rede("192.168.15.0/24"), ipaddress.ip_network("192.168.15.0/24"))
        self.assertEqual(scanner.ler_rede(" 192.168.15.0 "), ipaddress.ip_network("192.168.15.0/24"))
        self.assertEqual(scanner.ler_rede("192.168.15.77/24"), ipaddress.ip_network("192.168.15.0/24"))
        self.assertEqual(len(list(scanner.ler_rede("10.0.0.0/24").hosts())), 254)

    def test_invalidas(self):
        for ruim in ("abc", "300.1.1.0/24", "192.168.0.0/33"):
            with self.assertRaises(ValueError):
                scanner.ler_rede(ruim)

    def test_grande_demais(self):
        with self.assertRaises(ValueError):
            scanner.ler_rede("10.0.0.0/16")
        scanner.ler_rede("10.0.0.0/22")   # 1024 IPs: ainda aceita


class TestVerificarIp(unittest.TestCase):
    """A logica 'ping primeiro, ARP se o ping falhar', sem tocar na rede."""

    def test_respondeu_ping(self):
        with mock.patch.object(scanner, "fazer_ping", return_value=(3.0, 64)), \
             mock.patch.object(scanner, "sondar_arp", return_value="AA-BB-CC-DD-EE-01"), \
             mock.patch.object(scanner, "mac_da_tabela_arp", return_value="AA-BB-CC-DD-EE-01"):
            h = scanner.verificar_ip("10.0.0.5", 500, [])
        self.assertEqual((h.metodo, h.mac, h.tempo_ms, h.ttl), ("PING", "AA-BB-CC-DD-EE-01", 3.0, 64))

    def test_bloqueia_ping_mas_responde_arp(self):
        with mock.patch.object(scanner, "fazer_ping", return_value=None), \
             mock.patch.object(scanner, "sondar_arp", return_value="AA-BB-CC-DD-EE-02"):
            h = scanner.verificar_ip("10.0.0.6", 500, [])
        self.assertEqual((h.metodo, h.mac, h.tempo_ms), ("ARP", "AA-BB-CC-DD-EE-02", None))

    def test_ip_vazio(self):
        with mock.patch.object(scanner, "fazer_ping", return_value=None), \
             mock.patch.object(scanner, "sondar_arp", return_value=None):
            self.assertIsNone(scanner.verificar_ip("10.0.0.7", 500, []))

    def test_este_pc(self):
        with mock.patch.object(scanner, "mac_deste_pc", return_value="AA-BB-CC-DD-EE-03"), \
             mock.patch.object(scanner, "fazer_ping") as ping:
            h = scanner.verificar_ip("10.0.0.8", 500, ["10.0.0.8"])
        ping.assert_not_called()
        self.assertTrue(h.este_pc)

    def test_varrer_rede_ordena_e_avisa_cada_ip(self):
        def falso(ip, timeout, meus):
            return scanner.Host(ip, None, "PING", 1.0) if ip.endswith((".3", ".1")) else None
        vistos = []
        with mock.patch.object(scanner, "verificar_ip", side_effect=falso):
            hosts = scanner.varrer_rede(ipaddress.ip_network("10.0.0.0/29"), 100,
                                        lambda ip, h: vistos.append(ip))
        self.assertEqual([h.ip for h in hosts], ["10.0.0.1", "10.0.0.3"])
        self.assertEqual(len(vistos), 6)   # /29 = 6 IPs de host


class TestPortas(unittest.TestCase):
    """Sobe um servidor TCP de verdade em 127.0.0.1 e confere se o scan o encontra."""

    def setUp(self):
        self.servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servidor.bind(("127.0.0.1", 0))
        self.servidor.listen(16)
        self.porta = self.servidor.getsockname()[1]
        self.rodando = True
        threading.Thread(target=self._aceitar, daemon=True).start()

    def _aceitar(self):
        while self.rodando:
            try:
                conexao, _ = self.servidor.accept()
                conexao.close()
            except OSError:
                return

    def tearDown(self):
        self.rodando = False
        self.servidor.close()

    def test_acha_porta_aberta(self):
        abertas = scanner.escanear_portas("127.0.0.1", self.porta - 5, self.porta + 5, 300)
        self.assertIn(self.porta, abertas)
        self.assertEqual(abertas, sorted(abertas))

    def test_porta_aberta_e_fechada(self):
        self.assertTrue(scanner.porta_aberta("127.0.0.1", self.porta, 300))
        livre = socket.socket()
        livre.bind(("127.0.0.1", 0))
        porta_fechada = livre.getsockname()[1]
        livre.close()
        self.assertFalse(scanner.porta_aberta("127.0.0.1", porta_fechada, 300))

    def test_nomes(self):
        self.assertEqual(scanner.nome_porta(80), "80 (HTTP)")
        self.assertEqual(scanner.nome_porta(12345), "12345")


class TestTextoTempo(unittest.TestCase):
    def test_formatos(self):
        self.assertEqual(scanner.texto_tempo(None), "-")
        self.assertEqual(scanner.texto_tempo(0.4), "<1 ms")
        self.assertEqual(scanner.texto_tempo(2.87), "3 ms")
        self.assertEqual(scanner.texto_tempo(153), "153 ms")


class TestTtl(unittest.TestCase):
    def test_windows_e_linux(self):
        self.assertEqual(scanner.interpretar_ttl("Resposta de 192.168.15.1: bytes=32 tempo=4ms TTL=128"), 128)
        self.assertEqual(scanner.interpretar_ttl("64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.87 ms"), 64)
        self.assertIsNone(scanner.interpretar_ttl("Esgotado o tempo limite do pedido."))
        self.assertIsNone(scanner.interpretar_ttl(None))


class TestFabricante(unittest.TestCase):
    """Usa o fabricantes.txt de verdade, que vem no projeto."""

    def test_oui_de_24_bits(self):
        self.assertEqual(scanner.fabricante("F4-E8-4F-98-1B-94"), "ZTE")
        self.assertEqual(scanner.fabricante("A8-E6-21-A1-2D-07"), "Amazon")
        self.assertIn("Samsung", scanner.fabricante("00-7D-3B-20-1D-78"))

    def test_bloco_menor_tem_prioridade(self):
        # 00-1B-C5 e dividido em blocos de 36 bits, cada um de uma empresa diferente
        self.assertIn("Converging", scanner.fabricante("00-1B-C5-00-00-12"))
        self.assertIn("OpenRB", scanner.fabricante("00-1B-C5-00-10-12"))

    def test_mac_aleatorio_ou_vazio_nao_tem_fabricante(self):
        self.assertIsNone(scanner.fabricante("6A-25-C6-23-AF-B0"))
        self.assertIsNone(scanner.fabricante(None))

    def test_texto_da_coluna(self):
        self.assertEqual(scanner.texto_fabricante("F4-E8-4F-98-1B-94"), "ZTE")
        self.assertEqual(scanner.texto_fabricante("6A-25-C6-23-AF-B0"), "MAC aleatório (privado)")
        self.assertEqual(scanner.texto_fabricante("0C-00-00-00-00-01"), "-")
        self.assertEqual(scanner.texto_fabricante(None), "-")

    def test_propriedade_do_host(self):
        self.assertEqual(scanner.Host("10.0.0.1", "F4-E8-4F-00-00-01", "PING", 1).fabricante, "ZTE")


def _resposta_mdns(nome_ptr: str, com_pergunta: bool = True) -> bytes:
    """Monta uma resposta mDNS como a de um celular: 'meu nome e <nome_ptr>'."""
    def codificar(nome):
        return b"".join(bytes([len(p)]) + p.encode() for p in nome.split(".")) + b"\x00"
    pergunta = codificar("18.1.168.192.in-addr.arpa") + struct.pack(">HH", 12, 0x8001)
    rdata = codificar(nome_ptr)
    if com_pergunta:
        cab = struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0)
        resposta = b"\xc0\x0c"            # ponteiro para o nome da pergunta (compressao)
        corpo = pergunta
    else:
        cab = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        resposta = codificar("18.1.168.192.in-addr.arpa")
        corpo = b""
    resposta += struct.pack(">HHIH", 12, 0x8001, 120, len(rdata)) + rdata
    return cab + corpo + resposta


def _resposta_netbios(nomes) -> bytes:
    """Resposta NetBIOS Node Status com a lista (nome, sufixo, e_grupo)."""
    corpo = bytes([len(nomes)])
    for nome, sufixo, grupo in nomes:
        corpo += nome.ljust(15).encode() + bytes([sufixo]) + struct.pack(">H", 0x8400 if grupo else 0x0400)
    return b"\x00" * 56 + corpo


class TestNomes(unittest.TestCase):
    def test_mdns_com_compressao(self):
        self.assertEqual(scanner.interpretar_mdns(_resposta_mdns("Android.local")), "Android.local")

    def test_mdns_sem_pergunta(self):
        self.assertEqual(scanner.interpretar_mdns(_resposta_mdns("iPhone-de-Ana.local", False)),
                         "iPhone-de-Ana.local")

    def test_mdns_pacote_quebrado(self):
        self.assertIsNone(scanner.interpretar_mdns(b"\x00\x01\x02"))
        self.assertIsNone(scanner.interpretar_mdns(_resposta_mdns("Android.local")[:-6]))

    def test_pergunta_mdns_e_ptr_do_ip_invertido(self):
        q = scanner.pergunta_mdns("192.168.1.18")
        self.assertIn(b"\x0218\x011\x03168\x03192\x07in-addr\x04arpa\x00", q)
        self.assertEqual(q[-4:], struct.pack(">HH", 12, 0x8001))

    def test_netbios_pega_o_nome_do_computador_e_nao_o_grupo(self):
        dados = _resposta_netbios([("WORKGROUP", 0x00, True), ("DESKTOP-AB12CD", 0x00, False),
                                   ("DESKTOP-AB12CD", 0x20, False)])
        self.assertEqual(scanner.interpretar_netbios(dados), "DESKTOP-AB12CD")
        self.assertIsNone(scanner.interpretar_netbios(b"\x00" * 10))

    def test_limpar_nome(self):
        self.assertEqual(scanner.limpar_nome("Android.local.", "192.168.1.18"), "Android")
        self.assertEqual(scanner.limpar_nome("notebook-joao.lan", "192.168.1.9"), "notebook-joao")
        for inutil in ("localhost.local", "none.local", "unknown", "SpotifyConnect", "_gateway", "192.168.1.18", "192-168-1-18.provedor.net", "", None):
            self.assertIsNone(scanner.limpar_nome(inutil, "192.168.1.18"), inutil)

    def test_descobrir_nome_usa_o_primeiro_que_funcionar(self):
        with mock.patch.object(scanner, "nome_mdns", return_value=None), \
             mock.patch.object(scanner, "nome_netbios", return_value="DESKTOP-AB12CD"), \
             mock.patch.object(scanner, "nome_dns_reverso") as dns:
            self.assertEqual(scanner.descobrir_nome("10.0.0.2"), "DESKTOP-AB12CD")
        dns.assert_not_called()

    def test_mdns_de_verdade_numa_porta_local(self):
        """Um 'aparelho' falso em 127.0.0.1 responde a pergunta pela rede de verdade."""
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.bind(("127.0.0.1", 0))
        porta = servidor.getsockname()[1]

        def responder():
            _, origem = servidor.recvfrom(512)
            servidor.sendto(_resposta_mdns("Galaxy-S23.local"), origem)
        threading.Thread(target=responder, daemon=True).start()
        try:
            dados = scanner._perguntar_udp("127.0.0.1", porta, scanner.pergunta_mdns("127.0.0.1"), 2)
        finally:
            servidor.close()
        self.assertEqual(scanner.interpretar_mdns(dados), "Galaxy-S23.local")


class TestGateway(unittest.TestCase):
    def test_linux(self):
        saida = "default via 192.168.1.1 dev wlp3s0 proto dhcp src 192.168.1.154 metric 600\n"
        self.assertEqual(scanner.ler_gateway(saida), "192.168.1.1")

    def test_windows(self):
        saida = ("IPv4 Route Table\r\n=====\r\nActive Routes:\r\n"
                 "Network Destination        Netmask          Gateway       Interface  Metric\r\n"
                 "          0.0.0.0          0.0.0.0     192.168.15.1    192.168.15.6     35\r\n")
        self.assertEqual(scanner.ler_gateway(saida), "192.168.15.1")

    def test_sem_gateway(self):
        self.assertIsNone(scanner.ler_gateway(""))


class TestPalpiteTipo(unittest.TestCase):
    def host(self, mac="0C-00-00-00-00-01",   # prefixo nao registrado
             nome=None, portas=(), ttl=None, ip="10.0.0.9"):
        h = scanner.Host(ip, mac, "PING", 1, portas=list(portas), ttl=ttl)
        h.nome = nome
        return h

    def test_este_pc_e_roteador(self):
        self.assertEqual(scanner.palpite_tipo(scanner.Host("10.0.0.2", None, "PING", 0, este_pc=True)),
                         "Este computador")
        self.assertIn("Roteador", scanner.palpite_tipo(self.host(ip="10.0.0.1"), gateway="10.0.0.1"))

    def test_nome_e_a_pista_mais_forte(self):
        self.assertEqual(scanner.palpite_tipo(self.host(nome="iPhone-de-Ana")), "iPhone")
        self.assertEqual(scanner.palpite_tipo(self.host(nome="Android-2")), "Celular/tablet Android")
        self.assertEqual(scanner.palpite_tipo(self.host(nome="DESKTOP-AB12CD", portas=[22])),
                         "Computador Windows")

    def test_portas(self):
        self.assertEqual(scanner.palpite_tipo(self.host(portas=[80, 9100])), "Impressora")
        self.assertEqual(scanner.palpite_tipo(self.host(portas=[445, 139])), "Computador Windows")
        self.assertEqual(scanner.palpite_tipo(self.host(portas=[62078])), "iPhone/iPad")

    def test_fabricante(self):
        self.assertIn("Amazon", scanner.palpite_tipo(self.host(mac="A8-E6-21-A1-2D-07")))
        self.assertIn("Samsung", scanner.palpite_tipo(self.host(mac="00-7D-3B-20-1D-78")))

    def test_mac_aleatorio_e_ttl(self):
        self.assertIn("MAC privado", scanner.palpite_tipo(self.host(mac="6A-25-C6-23-AF-B0")))
        self.assertEqual(scanner.palpite_tipo(self.host(ttl=128)), "Computador Windows")
        self.assertEqual(scanner.palpite_tipo(self.host(ttl=255)), "Equipamento de rede")
        self.assertEqual(scanner.palpite_tipo(self.host()), "")


def _nome(n: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def _registro(dono: str, tipo: int, dados: bytes) -> bytes:
    return _nome(dono) + struct.pack(">HHIH", tipo, 0x8001, 120, len(dados)) + dados


def _txt(**pares) -> bytes:
    return b"".join(bytes([len(t)]) + t for t in ("%s=%s" % kv for kv in pares.items()) for t in [t.encode()])


def _resposta(perguntas, respostas, adicionais=()) -> bytes:
    """Resposta mDNS como a de um aparelho real: REPETE as perguntas (legacy unicast)."""
    corpo = b"".join(_nome(n) + struct.pack(">HH", 12, 0x8001) for n in perguntas)
    corpo += b"".join(respostas) + b"".join(adicionais)
    return struct.pack(">HHHHHH", 0, 0x8400, len(perguntas), len(respostas), 0, len(adicionais)) + corpo


class TestServicosMdns(unittest.TestCase):
    PERGUNTAS = ["_companion-link._tcp.local", "_airplay._tcp.local", "_services._dns-sd._udp.local"]

    def test_tv_com_airplay(self):
        dados = _resposta(self.PERGUNTAS,
                          [_registro("_airplay._tcp.local", 12, _nome("TV Sala._airplay._tcp.local"))],
                          [_registro("TV Sala._airplay._tcp.local", 16, _txt(model="Q70F", deviceid="00:7D"))])
        info = scanner.interpretar_servicos_mdns(dados)
        self.assertEqual((info.servicos, info.nome, info.modelo), ({"_airplay"}, "TV Sala", "Q70F"))

    def test_perguntas_repetidas_nao_viram_servicos(self):
        """Bug visto numa rede real: o Echo repetia as perguntas e parecia anunciar _companion-link."""
        dados = _resposta(self.PERGUNTAS,
                          [_registro("_services._dns-sd._udp.local", 12, _nome("_spotify-connect._tcp.local"))])
        self.assertEqual(scanner.interpretar_servicos_mdns(dados).servicos, {"_spotify-connect"})

    def test_iphone_pelo_modelo(self):
        dados = _resposta([], [_registro("_companion-link._tcp.local", 12,
                                         _nome("iPhone de Ana._companion-link._tcp.local"))],
                          [_registro("iPhone de Ana._companion-link._tcp.local", 16, _txt(rpMd="iPhone14,5"))])
        info = scanner.interpretar_servicos_mdns(dados)
        self.assertEqual((info.nome, info.modelo), ("iPhone de Ana", "iPhone14,5"))
        self.assertIn("_companion-link", info.servicos)

    def test_raop_tira_o_mac_do_nome_e_chromecast_usa_fn(self):
        raop = _resposta([], [_registro("_raop._tcp.local", 12, _nome("A1B2C3D4E5F6@Caixa Cozinha._raop._tcp.local"))])
        self.assertEqual(scanner.interpretar_servicos_mdns(raop).nome, "Caixa Cozinha")
        cast = _resposta([], [_registro("_googlecast._tcp.local", 12,
                                        _nome("Chromecast-8a1b2c3d4e5f6a7b._googlecast._tcp.local"))],
                         [_registro("Chromecast-8a1b2c3d4e5f6a7b._googlecast._tcp.local", 16,
                                    _txt(md="Chromecast", fn="TV do Quarto"))])
        info = scanner.interpretar_servicos_mdns(cast)
        self.assertEqual((info.nome, info.modelo), ("TV do Quarto", "Chromecast"))

    def test_pacote_quebrado(self):
        self.assertEqual(scanner.interpretar_servicos_mdns(b"\x00\x01").servicos, set())

    def test_descoberta_de_verdade_com_aparelho_falso(self):
        """Um 'aparelho' em 127.0.0.1 recebe as perguntas pela rede e responde."""
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.bind(("127.0.0.1", 0))
        resposta = _resposta([], [_registro("_companion-link._tcp.local", 12,
                                            _nome("MacBook do Joao._companion-link._tcp.local"))],
                             [_registro("MacBook do Joao._companion-link._tcp.local", 16,
                                        _txt(rpMd="MacBookPro18,1"))])

        def responder():
            _, origem = servidor.recvfrom(2048)
            servidor.sendto(resposta, origem)
        threading.Thread(target=responder, daemon=True).start()
        try:
            achados = scanner.descobrir_servicos_mdns(espera=1.0, destino=servidor.getsockname())
        finally:
            servidor.close()
        info = achados["127.0.0.1"]
        self.assertEqual((info.nome, info.modelo), ("MacBook do Joao", "MacBookPro18,1"))

    def test_aplicar_mdns_prefere_nome_amigavel(self):
        h = scanner.Host("10.0.0.2", None, "PING", 1)
        h.nome = "localhost-tecnico"
        scanner.aplicar_mdns(h, scanner.InfoMdns({"_airplay"}, "TV Sala", "Q70F"))
        self.assertEqual((h.nome, h.modelo, h.servicos), ("TV Sala", "Q70F", {"_airplay"}))
        scanner.aplicar_mdns(h, scanner.InfoMdns({"_googlecast"}, None, None))
        self.assertEqual((h.nome, h.servicos), ("TV Sala", {"_airplay", "_googlecast"}))


class TestPortasIdentificacao(unittest.TestCase):
    def test_so_testa_as_que_ficaram_fora_do_intervalo(self):
        testadas = []

        def falsa(ip, porta, timeout):
            testadas.append(porta)
            return porta == 62078
        with mock.patch.object(scanner, "porta_aberta", side_effect=falsa):
            abertas = scanner.escanear_portas_identificacao("10.0.0.5", 1, 1024, 300)
        self.assertEqual(abertas, [62078])
        self.assertNotIn(445, testadas)      # 445 ja esta no intervalo 1-1024
        self.assertIn(62078, testadas)

    def test_intervalo_que_cobre_tudo_nao_testa_nada(self):
        with mock.patch.object(scanner, "porta_aberta") as porta:
            self.assertEqual(scanner.escanear_portas_identificacao("10.0.0.5", 1, 65535, 300), [])
        porta.assert_not_called()


class TestPalpiteComMdns(unittest.TestCase):
    def host(self, mac="0C-00-00-00-00-01", **campos):
        h = scanner.Host("10.0.0.9", mac, "PING", 1)
        for chave, valor in campos.items():
            setattr(h, chave, valor)
        return h

    def test_modelo_apple(self):
        for modelo, tipo in (("iPhone14,5", "iPhone"), ("iPad13,1", "iPad"), ("MacBookPro18,1", "Mac (notebook)"),
                             ("Mac14,2", "Mac"), ("AppleTV11,1", "Apple TV"), ("AudioAccessory5,1", "HomePod")):
            self.assertEqual(scanner.palpite_tipo(self.host(modelo=modelo)), tipo, modelo)

    def test_servicos(self):
        self.assertIn("Apple", scanner.palpite_tipo(self.host(mac="6A-25-C6-23-AF-B0", servicos={"_companion-link"})))
        self.assertEqual(scanner.palpite_tipo(self.host(servicos={"_googlecast"})), "Chromecast / Google TV")
        self.assertEqual(scanner.palpite_tipo(self.host(servicos={"_ipp"})), "Impressora")

    def test_airplay_numa_tv_samsung_nao_e_apple(self):
        tv = self.host(mac="00-7D-3B-20-1D-78", servicos={"_airplay"})
        self.assertEqual(scanner.palpite_tipo(tv), "Smart TV (com AirPlay)")

    def test_iphone_com_mac_privado_pela_porta_62078(self):
        iphone = self.host(mac="6A-25-C6-23-AF-B0", portas_extras=[62078])
        self.assertEqual(scanner.palpite_tipo(iphone), "iPhone/iPad")


if __name__ == "__main__":
    unittest.main()
