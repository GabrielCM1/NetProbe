"""Testes do monitor sem exigir acesso privilegiado à interface de rede."""
import socket
import tkinter as tk
import unittest
from types import SimpleNamespace
from unittest import mock

import monitor_local as monitor


class TestTelemetria(unittest.TestCase):
    def test_soma_apenas_tcp_udp_recebidos_de_a_em_b(self):
        a, b = "10.0.0.1", "10.0.0.2"
        contadores = monitor.Contadores(b, a)
        for origem, destino, protocolo, tamanho in [
                (a, b, 6, 60), (a, b, 6, 1000), (a, b, 17, 800),
                (b, a, 6, 60), ("10.0.0.3", b, 17, 300), (a, b, 1, 64)]:
            contadores.receber(SimpleNamespace(src=origem, dst=destino, proto=protocolo, len=tamanho))
        contadores.receber(None)
        self.assertEqual(contadores.amostra(), (3, 1060, 800))
        self.assertEqual(monitor.volume(1860), "1.860 KB")

    def test_socket_tcp_em_escuta_e_conexao_real(self):
        try:
            import psutil
        except ImportError:
            self.skipTest("psutil opcional ausente")
        with socket.socket() as servidor, socket.socket() as cliente:
            servidor.bind(("127.0.0.1", 0))
            servidor.listen(1)
            ip, porta = servidor.getsockname()
            cliente.connect((ip, porta))
            with servidor.accept()[0]:
                linhas = monitor.conexoes_locais(psutil, ip, ip)
                self.assertIn(("LISTENING", ip, porta, "—", "—"), linhas)
                self.assertIn(("ESTABLISHED", ip, porta, ip, cliente.getsockname()[1]), linhas)
                self.assertFalse(any(l[0] == "ESTABLISHED" for l in
                                     monitor.conexoes_locais(psutil, ip, "192.0.2.17")))


class TestJanela(unittest.TestCase):
    def setUp(self):
        try:
            self.raiz = tk.Tk()
        except tk.TclError:
            self.skipTest("sem tela gráfica")
        self.addCleanup(self.raiz.destroy)
        self.raiz.withdraw()
        psutil = mock.Mock()
        psutil.net_if_addrs.return_value = {
            "Wi-Fi": [SimpleNamespace(family=socket.AF_INET, address="192.0.2.2")]}
        self.janela = monitor.MonitorLocal(self.raiz, psutil)
        self.janela.cliente.insert(0, "192.0.2.1")

    def test_taxa_totais_parada_e_reinicio(self):
        janela = self.janela
        with mock.patch("monitor_local.threading.Thread"), mock.patch.object(janela, "after"), \
                mock.patch("monitor_local.time.monotonic") as relogio:
            relogio.return_value = 10
            janela.iniciar()
            for protocolo in (6, 17):
                janela.contadores.receber(SimpleNamespace(src="192.0.2.1", dst="192.0.2.2",
                                                          proto=protocolo, len=500))
            relogio.return_value = 11
            janela._atualizar()
            self.assertIn("2.0 pps", janela.metricas.cget("text"))
            self.assertIn("Total: 1.000 KB", janela.metricas.cget("text"))
            janela.interromper()
            self.assertTrue(janela.parar.is_set())
            janela.eventos.put(("fim", None))
            janela._atualizar()
            self.assertIn("0.0 pps", janela.metricas.cget("text"))
            self.assertIn("Total: 1.000 KB", janela.metricas.cget("text"))
            janela.iniciar()
            self.assertEqual(janela.contadores.amostra(), (0, 0, 0))

    def test_falha_de_captura_permite_tentar_novamente(self):
        janela = self.janela
        with mock.patch("monitor_local.threading.Thread"), mock.patch.object(janela, "after"):
            janela.iniciar()
            janela.eventos.put(("erro", "Falha na captura: permissão negada"))
            janela.eventos.put(("fim", None))
            janela._atualizar()
            self.assertTrue(janela.iniciar_bt.instate(["!disabled"]))
            self.assertIn("permissão", janela.status.cget("text"))
