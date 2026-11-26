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
        for ip in self.app.hosts.keys() - {h.ip for h in hosts}:
            self.app.fila.put(("ip", ip, None))
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
        # O resultado do IP chega antes do fim da segunda varredura.
        self.app.fila.put(("ip", h.ip, None))
        self.app._processar_fila()
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
        self.assertIn("MAC aleatório", self.linha("10.0.0.3")["fabricante"])
        self.assertIn("MAC privado", self.linha("10.0.0.3")["tipo"])

    def test_fabricante_e_tipo_do_roteador(self):
        self.app.gateway = "10.0.0.1"
        self.rodada([scanner.Host("10.0.0.1", "F4-E8-4F-98-1B-94", "PING", 2, ttl=64)])
        self.assertEqual(self.linha("10.0.0.1")["fabricante"], "ZTE")
        self.assertIn("Roteador", self.linha("10.0.0.1")["tipo"])

    def test_nome_descoberto_aparece_e_fica_entre_rodadas(self):
        self.rodada([scanner.Host("10.0.0.7", "00-11-22-33-44-07", "PING", 2)])
        self.assertEqual(self.linha("10.0.0.7")["nome"], "-")
        self.app.fila.put(("nome", "10.0.0.7", "Android-2"))
        self.app._processar_fila()
        self.assertEqual(self.linha("10.0.0.7")["nome"], "Android-2")
        self.assertEqual(self.linha("10.0.0.7")["tipo"], "Celular/tablet Android")
        self.rodada([scanner.Host("10.0.0.7", "00-11-22-33-44-07", "ARP", None)])
        self.assertEqual(self.linha("10.0.0.7")["nome"], "Android-2")

    def test_outro_aparelho_no_ip_perde_o_nome_antigo(self):
        self.rodada([scanner.Host("10.0.0.7", "00-11-22-33-44-07", "PING", 2)])
        self.app.fila.put(("nome", "10.0.0.7", "Android-2"))
        self.rodada([scanner.Host("10.0.0.7", "00-11-22-33-44-99", "PING", 2)])
        self.assertEqual(self.linha("10.0.0.7")["nome"], "-")

    def test_arp_que_falhou_mantem_mac_anterior_sem_colisao(self):
        self.rodada([scanner.Host("10.0.0.4", "00-11-22-33-44-04", "PING", 2)])
        self.rodada([scanner.Host("10.0.0.4", None, "PING", 2)])
        self.assertEqual(self.linha("10.0.0.4")["mac"], "00-11-22-33-44-04")
        self.assertEqual(self.linha("10.0.0.4")["tag"], "online")


    def test_mdns_identifica_iphone_com_mac_privado(self):
        self.rodada([scanner.Host("10.0.0.56", "6A-25-C6-23-AF-B0", "ARP", None)])
        self.app.fila.put(("mdns", {"10.0.0.56": scanner.InfoMdns({"_companion-link"}, "iPhone de Ana",
                                                                  "iPhone14,5")}))
        self.app._processar_fila()
        linha = self.linha("10.0.0.56")
        self.assertEqual((linha["nome"], linha["tipo"]), ("iPhone de Ana", "iPhone"))
        self.assertIn("modelo iPhone14,5", linha["obs"])
        # Na rodada seguinte o iPhone "dormiu" e nao respondeu ao mDNS: o que ja se sabia fica
        self.rodada([scanner.Host("10.0.0.56", "6A-25-C6-23-AF-B0", "ARP", None)])
        self.assertEqual(self.linha("10.0.0.56")["tipo"], "iPhone")

    def test_porta_de_identificacao_vai_para_observacoes_e_nao_para_portas(self):
        self.rodada([scanner.Host("10.0.0.56", "6A-25-C6-23-AF-B0", "PING", 300)])
        self.app.fila.put(("portas", "10.0.0.56", [], [62078]))
        self.app._processar_fila()
        linha = self.linha("10.0.0.56")
        self.assertEqual(linha["portas"], "nenhuma no intervalo")
        self.assertIn("62078 (iPhone-sync)", linha["obs"])
        self.assertEqual(linha["tipo"], "iPhone/iPad")

    def test_nome_amigavel_do_mdns_ganha_do_nome_tecnico(self):
        self.rodada([scanner.Host("10.0.0.2", "00-7D-3B-20-1D-78", "PING", 2)])
        self.app.fila.put(("mdns", {"10.0.0.2": scanner.InfoMdns({"_airplay"}, "TV Sala", "Q70F")}))
        self.app.fila.put(("nome", "10.0.0.2", "tizen-tecnico"))
        self.app._processar_fila()
        self.assertEqual(self.linha("10.0.0.2")["nome"], "TV Sala")
        self.assertEqual(self.linha("10.0.0.2")["tipo"], "Smart TV")

if __name__ == "__main__":
    unittest.main()
