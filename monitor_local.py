"""Auditoria de sockets e telemetria IPv4 recebida pelo servidor B."""
import ipaddress
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk


def conexoes_locais(psutil, servidor, cliente):
    linhas = set()
    for conexao in psutil.net_connections(kind="tcp4"):
        ip, porta = conexao.laddr
        if conexao.status == "LISTEN" and ip in ("0.0.0.0", servidor):
            linhas.add(("LISTENING", ip, porta, "—", "—"))
        elif (conexao.status == "ESTABLISHED" and ip == servidor
              and conexao.raddr and conexao.raddr.ip == cliente):
            linhas.add(("ESTABLISHED", ip, porta, cliente, conexao.raddr.port))
    return sorted(linhas)


class Contadores:
    def __init__(self, servidor, cliente):
        self.servidor = servidor
        self.cliente = cliente
        self.tcp = self.udp = self.pacotes = 0
        self.trava = threading.Lock()

    def receber(self, ip):
        # ip.len é o tamanho do pacote IPv4 (inclui os cabeçalhos).
        if ip is None or ip.src != self.cliente or ip.dst != self.servidor:
            return
        if ip.proto not in (6, 17):
            return
        with self.trava:
            if ip.proto == 6:
                self.tcp += ip.len
            else:
                self.udp += ip.len
            self.pacotes += 1

    def amostra(self):
        with self.trava:
            return self.pacotes, self.tcp, self.udp


def auditar(psutil, servidor, cliente, parar, eventos):
    try:
        while not parar.is_set():
            eventos.put(("conexoes", conexoes_locais(psutil, servidor, cliente)))
            parar.wait(1)
    except Exception as erro:
        eventos.put(("erro", "Falha ao consultar conexões locais: %s" % erro))
        parar.set()


def monitorar(psutil, nome_interface, contadores, parar, eventos):
    auditoria = None
    try:
        from scapy.all import IP, conf, get_working_ifaces

        interface = next((i for i in get_working_ifaces()
                          if i.name == nome_interface and contadores.servidor in i.ips.get(4, [])), None)
        if interface is None:
            raise RuntimeError("A interface selecionada não está disponível para captura.")
        # Um socket passivo, fora do modo promíscuo. Nenhum pacote fica armazenado.
        with conf.L2listen(iface=interface, promisc=False) as captura:
            if parar.is_set():
                return
            eventos.put(("pronto", time.monotonic()))
            auditoria = threading.Thread(target=auditar, daemon=True, args=(
                psutil, contadores.servidor, contadores.cliente, parar, eventos))
            auditoria.start()
            while not parar.is_set():
                if captura.select([captura], remain=0.25):
                    pacote = captura.recv()
                    if pacote is not None:
                        contadores.receber(pacote.getlayer(IP))
    except Exception as erro:
        eventos.put(("erro", "Falha na captura. Confira a permissão de captura no Linux "
                    "ou a instalação do Npcap no Windows. Detalhe: %s" % erro))
    finally:
        parar.set()
        if auditoria is not None:
            auditoria.join()
        eventos.put(("fim", None))


def volume(n):
    if n >= 1000000:
        return "%.3f MB" % (n / 1000000)
    return "%.3f KB" % (n / 1000)


class MonitorLocal(tk.Toplevel):
    def __init__(self, parent, psutil):
        super().__init__(parent)
        self.psutil = psutil
        self.title("NetProbe — Monitor local")
        self.parar = None
        self.agendamento = None
        self.bind("<Destroy>", self._ao_destruir, add="+")
        painel = ttk.Frame(self, padding=12)
        painel.pack(fill="both", expand=True)
        self.enderecos = {}
        try:
            for nome, enderecos in psutil.net_if_addrs().items():
                for addr in enderecos:
                    if addr.family == socket.AF_INET and not ipaddress.ip_address(addr.address).is_loopback:
                        self.enderecos[f"{nome} — {addr.address}"] = (nome, addr.address)
        except Exception as erro:
            messagebox.showerror("Monitor local", str(erro), parent=self)
        ttk.Label(painel, text="Interface e IPv4 do servidor B").grid(row=0, column=0, sticky="w")
        ttk.Label(painel, text="IPv4 do cliente A").grid(row=0, column=1, sticky="w")
        self.interface = ttk.Combobox(painel, values=list(self.enderecos), width=34, state="readonly")
        self.interface.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        if self.enderecos:
            self.interface.current(0)
        self.cliente = ttk.Entry(painel, width=18)
        self.cliente.grid(row=1, column=1, padx=(0, 8))
        self.iniciar_bt = ttk.Button(painel, text="Iniciar", command=self.iniciar)
        self.iniciar_bt.grid(row=1, column=2)
        self.parar_bt = ttk.Button(painel, text="Parar", command=self.interromper, state="disabled")
        self.parar_bt.grid(row=1, column=3)
        self.status = ttk.Label(painel, text="Escolha a interface e informe o IP do cliente."
                                if self.enderecos else "Nenhuma interface IPv4 de rede encontrada.",
                                wraplength=650)
        self.status.grid(row=2, column=0, columnspan=4, sticky="w", pady=8)
        self.metricas = ttk.Label(painel, text="Recepção de A → B")
        self.metricas.grid(row=3, column=0, columnspan=4, sticky="w", pady=6)
        colunas = ("Estado TCP", "IP local", "Porta local", "IP remoto", "Porta remota")
        self.tabela = ttk.Treeview(painel, columns=colunas, show="headings", height=12)
        for coluna in colunas:
            self.tabela.heading(coluna, text=coluna)
            self.tabela.column(coluna, width=125, anchor="center")
        self.tabela.grid(row=4, column=0, columnspan=4, sticky="nsew")
        barra = ttk.Scrollbar(painel, command=self.tabela.yview)
        barra.grid(row=4, column=4, sticky="ns")
        self.tabela.configure(yscrollcommand=barra.set)
        painel.rowconfigure(4, weight=1)
        painel.columnconfigure(0, weight=1)

    def iniciar(self):
        interface, servidor = self.enderecos.get(self.interface.get(), (None, None))
        try:
            cliente = ipaddress.IPv4Address(self.cliente.get().strip())
            if not servidor or str(cliente) == servidor or cliente.is_multicast or cliente.is_unspecified:
                raise ValueError
        except ValueError:
            messagebox.showerror("Monitor local", "Selecione a interface de B e informe o IPv4 de A.",
                                 parent=self)
            return
        self.parar = threading.Event()
        self.eventos = queue.Queue()
        self.contadores = Contadores(servidor, str(cliente))
        self.falhou = False
        self.ultimo_total = 0
        self.ultima_amostra = time.monotonic()
        self.tabela.delete(*self.tabela.get_children())
        self.iniciar_bt.configure(state="disabled")
        self.interface.configure(state="disabled")
        self.cliente.configure(state="disabled")
        self.parar_bt.configure(state="normal")
        self.status.configure(text="Abrindo a captura…")
        self._mostrar_metricas(0, 0, 0)
        threading.Thread(target=monitorar, daemon=True, args=(
            self.psutil, interface, self.contadores, self.parar, self.eventos)).start()
        self._atualizar()

    def interromper(self):
        self.parar.set()
        self.parar_bt.configure(state="disabled")

    def _ao_destruir(self, evento):
        if evento.widget is self:
            if self.parar is not None:
                self.parar.set()
            if self.agendamento is not None:
                self.after_cancel(self.agendamento)

    def _mostrar_metricas(self, taxa, tcp, udp):
        self.metricas.configure(text=f"Recepção: {taxa:.1f} pps     TCP: {volume(tcp)}     "
                                f"UDP: {volume(udp)}     Total: {volume(tcp + udp)}")

    def _atualizar(self):
        self.agendamento = None
        terminou = False
        try:
            while True:
                evento, valor = self.eventos.get_nowait()
                if evento == "pronto":
                    self.status.configure(text="Capturando pacotes IPv4 TCP e UDP de A para B.")
                    self.ultima_amostra = valor
                elif evento == "erro":
                    self.falhou = True
                    self.status.configure(text=valor)
                elif evento == "conexoes":
                    self.tabela.delete(*self.tabela.get_children())
                    for linha in valor:
                        self.tabela.insert("", "end", values=linha)
                elif evento == "fim":
                    terminou = True
        except queue.Empty:
            pass
        agora = time.monotonic()
        intervalo = agora - self.ultima_amostra
        if terminou or intervalo >= 1:
            total, tcp, udp = self.contadores.amostra()
            taxa = 0 if terminou else (total - self.ultimo_total) / intervalo
            self._mostrar_metricas(taxa, tcp, udp)
            self.ultima_amostra, self.ultimo_total = agora, total
        if terminou:
            if not self.falhou:
                self.status.configure(text="Monitoramento encerrado.")
            self.iniciar_bt.configure(state="normal")
            self.interface.configure(state="readonly")
            self.cliente.configure(state="normal")
            self.parar_bt.configure(state="disabled")
        else:
            self.agendamento = self.after(200, self._atualizar)


def abrir_monitor(parent):
    try:
        import psutil
        import scapy
    except ImportError:
        messagebox.showerror("Monitor local", "Instale as dependências do monitor com "
                             "python -m pip install -r requirements-monitor.txt", parent=parent)
        return
    for janela in parent.winfo_children():
        if isinstance(janela, MonitorLocal):
            janela.deiconify()
            janela.lift()
            return
    MonitorLocal(parent, psutil)
