"""Testes da parte de rede (scanner.py).

Rodar (na pasta do projeto):  python -m unittest discover -s tests -v

Os testes de interpretacao usam saidas reais dos comandos (Windows em portugues
e ingles, Linux), entao funcionam em qualquer sistema, sem rede.
"""
import ipaddress
import socket
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
        with mock.patch.object(scanner, "fazer_ping", return_value=3.0), \
             mock.patch.object(scanner, "sondar_arp", return_value="AA-BB-CC-DD-EE-01"), \
             mock.patch.object(scanner, "mac_da_tabela_arp", return_value="AA-BB-CC-DD-EE-01"):
            h = scanner.verificar_ip("10.0.0.5", 500, [])
        self.assertEqual((h.metodo, h.mac, h.tempo_ms), ("PING", "AA-BB-CC-DD-EE-01", 3.0))

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


if __name__ == "__main__":
    unittest.main()
