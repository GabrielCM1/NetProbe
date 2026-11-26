"""Auditoria de sockets e telemetria IPv4 recebida pelo servidor B."""
# ==========================================================================
# MAPA DESTE ARQUIVO (versão comentada, para estudo)  -  escopo 4.2 do professor
# ==========================================================================
# Roda no SERVIDOR B. Mostra, ao vivo, o que o cliente A está fazendo com B:
#
#   1) Portas em escuta (LISTENING) .......... conexoes_locais()   via psutil
#   2) Conexões estabelecidas (ESTABLISHED) .. conexoes_locais()   via psutil
#   3) Pacotes por segundo (pps) ............. _atualizar()        conta pacotes a cada ~1 s
#   4) Volume acumulado (KB/MB) .............. Contadores.receber() soma o tamanho IPv4
#   5) Separação TCP x UDP ................... Contadores.receber() olha o campo "proto"
#
# São TRÊS threads:
#
#   TELA (MonitorLocal)          CAPTURA (monitorar)              AUDITORIA (auditar)
#   -------------------          -------------------              -------------------
#   clique em Iniciar
#     iniciar() --- cria --->    abre a placa de rede (scapy)
#                                fila.put("pronto")
#                                cria ------------------------->  a cada 1 s:
#                                a cada pacote recebido:            conexoes_locais()
#                                  contadores.receber(pacote)       fila.put("conexoes")
#   _atualizar() a cada 200 ms
#     lê a fila de eventos       (ao parar: fila.put("fim"))
#     lê os contadores e calcula pps / KB / MB
#
# Bibliotecas externas (requirements-monitor.txt):
#   psutil -> pergunta ao sistema quais sockets existem e em que estado (LISTEN, ESTABLISHED)
#   scapy  -> abre a placa de rede e entrega cada pacote que passa (captura ao vivo).
#             No Windows precisa do Npcap instalado; no Linux, de permissão de captura.
# ==========================================================================
import ipaddress   # validar o IP digitado e descartar o loopback (127.0.0.1)
import queue       # fila de eventos das threads de trabalho para a tela
import socket      # só a constante AF_INET (= IPv4)
import threading   # threads, trava (Lock) e "bandeira" de parar (Event)
import time        # relógio para calcular pacotes por segundo
import tkinter as tk
from tkinter import messagebox, ttk


# --------------------------------------------------------------------------
# Itens 1 e 2: portas em escuta e conexões estabelecidas
# --------------------------------------------------------------------------
def conexoes_locais(psutil, servidor, cliente):
    # Devolve as linhas da tabela: (estado, IP local, porta local, IP remoto, porta remota).
    # Usa um "set" para não repetir linhas iguais.
    linhas = set()
    # Passo 1: pede ao sistema TODOS os sockets TCP IPv4 do computador.
    # (É o mesmo que o comando "netstat -an" mostra.)
    for conexao in psutil.net_connections(kind="tcp4"):
        ip, porta = conexao.laddr                 # laddr = endereço LOCAL (IP e porta de B)
        # Passo 2: porta em ESCUTA. Um programa (servidor) está esperando conexões.
        # Só mostra as que escutam no IP de B ou em "0.0.0.0" (= em todas as placas).
        if conexao.status == "LISTEN" and ip in ("0.0.0.0", servidor):
            linhas.add(("LISTENING", ip, porta, "—", "—"))
        # Passo 3: conexão ESTABELECIDA. O handshake TCP já terminou e há uma conversa
        # em andamento. Só mostra as que são entre B e o cliente A (raddr = endereço REMOTO).
        elif (conexao.status == "ESTABLISHED" and ip == servidor
              and conexao.raddr and conexao.raddr.ip == cliente):
            linhas.add(("ESTABLISHED", ip, porta, cliente, conexao.raddr.port))
    # Passo 4: devolve em ordem (LISTENING e ESTABLISHED agrupados).
    return sorted(linhas)


# --------------------------------------------------------------------------
# Itens 4 e 5: contadores de volume, separados por TCP e UDP
# --------------------------------------------------------------------------
class Contadores:
    # Guarda os totais. Como a thread de CAPTURA escreve e a thread da TELA lê,
    # tudo passa por uma trava (Lock), para uma não ler no meio da escrita da outra.
    def __init__(self, servidor, cliente):
        self.servidor = servidor
        self.cliente = cliente
        self.tcp = self.udp = self.pacotes = 0    # bytes TCP, bytes UDP, nº de pacotes
        self.trava = threading.Lock()

    def receber(self, ip):
        # Chamado para CADA pacote capturado. "ip" é o cabeçalho IPv4 do pacote (scapy).
        # ip.len é o tamanho do pacote IPv4 (inclui os cabeçalhos).
        # Passo 1: só conta pacotes que vão de A (origem) para B (destino).
        if ip is None or ip.src != self.cliente or ip.dst != self.servidor:
            return
        # Passo 2: o campo "proto" do cabeçalho IP diz o protocolo de transporte:
        # 6 = TCP, 17 = UDP. Outros (ex.: 1 = ICMP do ping) são ignorados.
        if ip.proto not in (6, 17):
            return
        # Passo 3: soma o tamanho no contador do protocolo certo e conta mais 1 pacote.
        with self.trava:
            if ip.proto == 6:
                self.tcp += ip.len
            else:
                self.udp += ip.len
            self.pacotes += 1

    def amostra(self):
        # Fotografia dos contadores, lida pela tela a cada ~1 s.
        with self.trava:
            return self.pacotes, self.tcp, self.udp


# --------------------------------------------------------------------------
# Thread de AUDITORIA (itens 1 e 2)
# --------------------------------------------------------------------------
def auditar(psutil, servidor, cliente, parar, eventos):
    # A cada 1 segundo, relê as conexões e manda a lista para a tela pela fila.
    try:
        while not parar.is_set():
            eventos.put(("conexoes", conexoes_locais(psutil, servidor, cliente)))
            # wait(1) espera 1 s, mas acorda na hora se clicarem em Parar.
            parar.wait(1)
    except Exception as erro:
        eventos.put(("erro", "Falha ao consultar conexões locais: %s" % erro))
        parar.set()


# --------------------------------------------------------------------------
# Thread de CAPTURA DE PACOTES AO VIVO (itens 3, 4 e 5)
# --------------------------------------------------------------------------
def monitorar(psutil, nome_interface, contadores, parar, eventos):
    auditoria = None
    try:
        # scapy só é importado aqui, para o NetProbe abrir mesmo sem ele instalado.
        from scapy.all import IP, conf, get_working_ifaces

        # Passo 1: acha a placa de rede escolhida na tela, conferindo que ela tem o IP de B.
        interface = next((i for i in get_working_ifaces()
                          if i.name == nome_interface and contadores.servidor in i.ips.get(4, [])), None)
        if interface is None:
            raise RuntimeError("A interface selecionada não está disponível para captura.")
        # Passo 2: abre a captura na camada 2 (L2 = quadros Ethernet/Wi-Fi inteiros).
        # promisc=False: só vê o tráfego endereçado a esta máquina, e não o da rede toda.
        # Um socket passivo, fora do modo promíscuo. Nenhum pacote fica armazenado.
        with conf.L2listen(iface=interface, promisc=False) as captura:
            if parar.is_set():
                return
            # Passo 3: avisa a tela que a captura começou (e a hora, para calcular o pps).
            eventos.put(("pronto", time.monotonic()))
            # Passo 4: inicia a thread de AUDITORIA (portas e conexões) em paralelo.
            auditoria = threading.Thread(target=auditar, daemon=True, args=(
                psutil, contadores.servidor, contadores.cliente, parar, eventos))
            auditoria.start()
            # Passo 5: laço de captura. select() espera até 0,25 s por um pacote; esse
            # limite é o que permite conferir o botão Parar várias vezes por segundo.
            while not parar.is_set():
                if captura.select([captura], remain=0.25):
                    pacote = captura.recv()               # pega o quadro que chegou
                    if pacote is not None:
                        # getlayer(IP) tira só o cabeçalho IPv4 (None se não for IPv4).
                        contadores.receber(pacote.getlayer(IP))
    except Exception as erro:
        eventos.put(("erro", "Falha na captura. Confira a permissão de captura no Linux "
                    "ou a instalação do Npcap no Windows. Detalhe: %s" % erro))
    finally:
        # Passo 6: ao sair (Parar, erro ou janela fechada), garante que a auditoria
        # também pare, espera ela terminar e avisa a tela.
        parar.set()
        if auditoria is not None:
            auditoria.join()
        eventos.put(("fim", None))


def volume(n):
    # Formata bytes: KB = 1.000 bytes, MB = 1.000.000 bytes (padrão decimal).
    if n >= 1000000:
        return "%.3f MB" % (n / 1000000)
    return "%.3f KB" % (n / 1000)


# --------------------------------------------------------------------------
# A janela do Monitor local
# --------------------------------------------------------------------------
class MonitorLocal(tk.Toplevel):
    # Toplevel = uma janela extra, que abre por cima da janela principal do NetProbe.
    def __init__(self, parent, psutil):
        super().__init__(parent)
        self.psutil = psutil
        self.title("NetProbe — Monitor local")
        self.parar = None
        self.agendamento = None
        # Se a janela for fechada, _ao_destruir para a captura (não deixa thread solta).
        self.bind("<Destroy>", self._ao_destruir, add="+")
        painel = ttk.Frame(self, padding=12)
        painel.pack(fill="both", expand=True)
        # Passo 1: lista as placas de rede com IPv4 (menos o loopback 127.0.0.1),
        # no formato "Wi-Fi — 192.168.15.6" -> ("Wi-Fi", "192.168.15.6").
        self.enderecos = {}
        try:
            for nome, enderecos in psutil.net_if_addrs().items():
                for addr in enderecos:
                    if addr.family == socket.AF_INET and not ipaddress.ip_address(addr.address).is_loopback:
                        self.enderecos[f"{nome} — {addr.address}"] = (nome, addr.address)
        except Exception as erro:
            messagebox.showerror("Monitor local", str(erro), parent=self)
        # Passo 2: monta os campos: placa/IP de B (lista), IP de A (texto) e os botões.
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
        # Passo 3: a linha das métricas (pps, TCP, UDP, total) e a tabela de conexões.
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
        # Roda quando clicam em "Iniciar".
        # Passo 1: lê a placa/IP de B e valida o IP de A (não pode ser vazio, igual ao
        # de B, multicast ou 0.0.0.0).
        interface, servidor = self.enderecos.get(self.interface.get(), (None, None))
        try:
            cliente = ipaddress.IPv4Address(self.cliente.get().strip())
            if not servidor or str(cliente) == servidor or cliente.is_multicast or cliente.is_unspecified:
                raise ValueError
        except ValueError:
            messagebox.showerror("Monitor local", "Selecione a interface de B e informe o IPv4 de A.",
                                 parent=self)
            return
        # Passo 2: zera tudo para uma medição nova (bandeira, fila, contadores, tabela).
        self.parar = threading.Event()
        self.eventos = queue.Queue()
        self.contadores = Contadores(servidor, str(cliente))
        self.falhou = False
        self.ultimo_total = 0
        self.ultima_amostra = time.monotonic()
        self.tabela.delete(*self.tabela.get_children())
        # Passo 3: trava os campos enquanto mede e libera o botão Parar.
        self.iniciar_bt.configure(state="disabled")
        self.interface.configure(state="disabled")
        self.cliente.configure(state="disabled")
        self.parar_bt.configure(state="normal")
        self.status.configure(text="Abrindo a captura…")
        self._mostrar_metricas(0, 0, 0)
        # Passo 4: cria a thread de CAPTURA (que depois cria a de AUDITORIA)
        # e começa o laço de atualização da tela.
        threading.Thread(target=monitorar, daemon=True, args=(
            self.psutil, interface, self.contadores, self.parar, self.eventos)).start()
        self._atualizar()

    def interromper(self):
        # Botão Parar: levanta a bandeira. As threads percebem em até 0,25 s.
        # Os números ficam na tela; só um novo "Iniciar" zera.
        self.parar.set()
        self.parar_bt.configure(state="disabled")

    def _ao_destruir(self, evento):
        # Janela fechada: para as threads e cancela o próximo _atualizar agendado.
        if evento.widget is self:
            if self.parar is not None:
                self.parar.set()
            if self.agendamento is not None:
                self.after_cancel(self.agendamento)

    def _mostrar_metricas(self, taxa, tcp, udp):
        self.metricas.configure(text=f"Recepção: {taxa:.1f} pps     TCP: {volume(tcp)}     "
                                f"UDP: {volume(udp)}     Total: {volume(tcp + udp)}")

    def _atualizar(self):
        # Roda a cada 200 ms na thread da TELA.
        self.agendamento = None
        terminou = False
        # Passo 1: aplica todos os eventos que as threads mandaram pela fila.
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
                    # Redesenha a tabela inteira com a lista nova de conexões.
                    self.tabela.delete(*self.tabela.get_children())
                    for linha in valor:
                        self.tabela.insert("", "end", values=linha)
                elif evento == "fim":
                    terminou = True
        except queue.Empty:
            pass
        # Passo 2 (item 3): a cada ~1 s, calcula os PACOTES POR SEGUNDO:
        #   pps = (pacotes agora - pacotes na última amostra) / segundos que passaram
        # e mostra os volumes acumulados (itens 4 e 5).
        agora = time.monotonic()
        intervalo = agora - self.ultima_amostra
        if terminou or intervalo >= 1:
            total, tcp, udp = self.contadores.amostra()
            taxa = 0 if terminou else (total - self.ultimo_total) / intervalo
            self._mostrar_metricas(taxa, tcp, udp)
            self.ultima_amostra, self.ultimo_total = agora, total
        # Passo 3: se acabou, libera os campos; senão, agenda a próxima atualização.
        if terminou:
            if not self.falhou:
                self.status.configure(text="Monitoramento encerrado.")
            self.iniciar_bt.configure(state="normal")
            self.interface.configure(state="readonly")
            self.cliente.configure(state="normal")
            self.parar_bt.configure(state="disabled")
        else:
            self.agendamento = self.after(200, self._atualizar)


# --------------------------------------------------------------------------
# Ponto de entrada (chamado pelo botão "Monitor local" do app.py)
# --------------------------------------------------------------------------
def abrir_monitor(parent):
    # Passo 1: confere se psutil e scapy estão instalados. Se não estiverem, mostra
    # uma janela explicando como instalar (em vez de dar erro e fechar o programa).
    try:
        import psutil
        import scapy
    except ImportError as erro:
        aviso = parent.children.get("dependencias_monitor")
        if aviso is None:
            aviso = tk.Toplevel(parent, name="dependencias_monitor")
            aviso.title("Dependências do Monitor local")
            texto = (f"O Monitor local precisa de psutil e scapy. Falha ao carregar: {erro}.\n\n"
                     "Com pip: python -m pip install -r requirements-monitor.txt\n"
                     "Sem pip no Linux: veja no README a instalação pelo sistema.\n"
                     "Depois, reabra o NetProbe com o Python em que os pacotes foram instalados.")
            ttk.Label(aviso, text=texto, wraplength=480, padding=12).pack()
            ttk.Button(aviso, text="Fechar", command=aviso.destroy).pack(pady=(0, 10))
        aviso.deiconify()
        aviso.lift()
        return
    # Passo 2: se o Monitor já estiver aberto, só traz para a frente (não abre dois).
    for janela in parent.winfo_children():
        if isinstance(janela, MonitorLocal):
            janela.deiconify()
            janela.lift()
            return
    # Passo 3: abre a janela.
    MonitorLocal(parent, psutil)
