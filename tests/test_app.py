"""Testes da interface (app.py): status online/offline e deteccao de colisao de IP.

Nao faz varredura de verdade: injeta mensagens na fila, como a thread de varredura faria.
Precisa de uma tela grafica; se nao houver, os testes sao pulados.
"""
import sys
import tkinter as tk
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402
import scanner  # noqa: E402


class TestInterface(unittest.TestCase):
    def setUp(self):
        try:
            self.raiz = tk.Tk()
        except tk.TclError:
            self.skipTest("sem tela grafica")
        self.raiz.withdraw()
        self.app = app.NetProbeApp(self.raiz)
        self.app.params = {"intervalo": 10}

    def tearDown(self):
        self.raiz.destroy()

    def rodada(self, hosts):
        """Simula uma rodada completa da varredura com estes hosts online."""
        self.app.fila.put(("inicio", 254, "10.0.0.0/24"))
        for h in hosts:
            self.app.fila.put(("ip", h.ip, h))
        self.app.fila.put(("varredura_ok", [h.ip for h in hosts], 1.0))
        self.app._processar_fila()

    def linha(self, ip):
        nomes = [c[0] for c in self.app.colunas]
        valores = dict(zip(nomes, self.app.tabela.item(ip, "values")))
        valores["tag"] = self.app.tabela.item(ip, "tags")[0]
        return valores

    def test_ping_e_arp_aparecem_com_cores_diferentes(self):
        self.rodada([scanner.Host("10.0.0.1", "00-11-22-33-44-01", "PING", 2.6),
                     scanner.Host("10.0.0.2", "00-11-22-33-44-02", "ARP", None)])
        self.assertEqual(self.linha("10.0.0.1")["tag"], "online")
        self.assertEqual(self.linha("10.0.0.1")["tempo"], "3 ms")
        self.assertEqual(self.linha("10.0.0.2")["tag"], "arp")
        self.assertEqual(self.linha("10.0.0.2")["metodo"], "ARP (bloqueia ping)")

    def test_offline_so_depois_de_duas_faltas(self):
        h = scanner.Host("10.0.0.1", "00-11-22-33-44-01", "PING", 2)
        self.rodada([h])
        self.rodada([])
        self.assertEqual(self.linha("10.0.0.1")["tag"], "online")    # 1 falta: tolera
        self.rodada([])
        self.assertEqual(self.linha("10.0.0.1")["tag"], "offline")   # 2 faltas: offline
        self.rodada([scanner.Host("10.0.0.1", "00-11-22-33-44-01", "PING", 2)])
        self.assertEqual(self.linha("10.0.0.1")["tag"], "online")    # voltou

    def test_colisao_de_ip_quando_mac_muda(self):
        self.rodada([scanner.Host("10.0.0.5", "00-11-22-33-44-AA", "PING", 2)])
        self.rodada([scanner.Host("10.0.0.5", "00-11-22-33-44-BB", "PING", 2)])
        linha = self.linha("10.0.0.5")
        self.assertEqual(linha["tag"], "conflito")
        self.assertEqual(linha["mac"], "00-11-22-33-44-BB")
        self.assertIn("COLISÃO DE IP", linha["obs"])
        self.assertIn("00-11-22-33-44-AA", linha["obs"])
        self.assertIn("Colisões de IP: 1", self.app.lbl_resumo.cget("text"))

    def test_ip_reaproveitado_pelo_dhcp_nao_e_colisao(self):
        self.rodada([scanner.Host("10.0.0.5", "00-11-22-33-44-AA", "PING", 2)])
        self.rodada([]); self.rodada([])                              # ficou offline
        self.rodada([scanner.Host("10.0.0.5", "00-11-22-33-44-BB", "PING", 2)])
        self.assertEqual(self.linha("10.0.0.5")["tag"], "online")
        self.assertNotIn("10.0.0.5", self.app.conflitos)

    def test_mesmo_mac_em_dois_ips(self):
        self.rodada([scanner.Host("10.0.0.1", "00-11-22-33-44-01", "PING", 2),
                     scanner.Host("10.0.0.9", "00-11-22-33-44-01", "ARP", None)])
        self.assertIn("mesmo MAC que 10.0.0.9", self.linha("10.0.0.1")["obs"])
        self.assertIn("mesmo MAC que 10.0.0.1", self.linha("10.0.0.9")["obs"])

    def test_mac_aleatorio_sinalizado(self):
        self.rodada([scanner.Host("10.0.0.3", "6A-25-C6-23-AF-B0", "PING", 2)])
        self.assertIn("MAC aleatório", self.linha("10.0.0.3")["obs"])

    def test_arp_que_falhou_mantem_mac_anterior_sem_colisao(self):
        self.rodada([scanner.Host("10.0.0.4", "00-11-22-33-44-04", "PING", 2)])
        self.rodada([scanner.Host("10.0.0.4", None, "PING", 2)])
        self.assertEqual(self.linha("10.0.0.4")["mac"], "00-11-22-33-44-04")
        self.assertEqual(self.linha("10.0.0.4")["tag"], "online")


if __name__ == "__main__":
    unittest.main()
