"""
NetProbe Wi-Fi - INTERFACE (janela).

Abre uma janela com:
  - campos para escolher a rede, os timeouts e o intervalo de portas;
  - uma tabela que vai se preenchendo em TEMPO REAL com IP, MAC, status e portas;
  - identificacao de cada aparelho: nome, fabricante e tipo provavel;
  - modo "monitorar", que repete a varredura sozinho e marca quem saiu da rede como OFFLINE;
  - alerta de COLISAO DE IP quando o MAC de um IP muda entre uma rodada e outra;
  - exportacao da tabela IP/MAC para CSV.

Toda a parte de rede esta em scanner.py. Este arquivo so cuida da tela.
Para rodar:  python app.py
"""
import csv
import ipaddress
import queue
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import filedialog, messagebox, ttk

import scanner
from monitor_local import abrir_monitor

# Fontes comuns em cada sistema (se faltar alguma, o Tk usa a padrao)
FONTE = ("Segoe UI", 10) if scanner.WINDOWS else ("DejaVu Sans", 10)
FONTE_LOG = ("Consolas", 9) if scanner.WINDOWS else ("DejaVu Sans Mono", 9)

# Quantos aparelhos tem as portas verificadas ao mesmo tempo (cada um usa 200 conexoes)
HOSTS_EM_PARALELO = 3


class NetProbeApp:
    def __init__(self, janela: tk.Tk):
        self.janela = janela
        janela.title("NetProbe Wi-Fi")
        janela.geometry("1400x700")
        janela.minsize(900, 560)

        # Estado do programa
        self.hosts = {}            # ip -> scanner.Host (todos que ja apareceram)
        self.status = {}           # ip -> "online" | "arp" | "offline"
        self.visto = {}            # ip -> hora em que foi visto pela ultima vez
        self.faltas = {}           # ip -> quantas rodadas seguidas ele nao apareceu
        self.conflitos = {}        # ip -> MAC antigo, quando o MAC do IP mudou (colisao de IP)
        self.portas_feitas = set() # ips que ja tiveram as portas verificadas
        self.fila = queue.Queue()  # mensagens da thread de varredura para a tela
        self.parar_evento = threading.Event()
        self.rodando = False
        self.proxima_rodada = None # agendamento do modo monitorar
        self.rodada = 0
        self.gateway = None        # IP do roteador, para o palpite do tipo de aparelho

        self._montar_tela()
        self._processar_fila()     # comeca a "escutar" a fila

    # ------------------------------------------------------------------ tela
    def _montar_tela(self):
        estilo = ttk.Style()
        estilo.configure("Treeview", rowheight=24, font=FONTE)
        estilo.configure("Treeview.Heading", font=FONTE + ("bold",))

        # --- configuracoes
        cfg = ttk.LabelFrame(self.janela, text="Configuração", padding=10)
        cfg.pack(fill="x", padx=10, pady=(10, 5))

        redes = scanner.redes_sugeridas() or ["192.168.0.0/24"]
        self.var_rede = tk.StringVar(value=redes[0])
        self.var_timeout_ping = tk.StringVar(value="500")
        self.var_porta_ini = tk.StringVar(value="1")
        self.var_porta_fim = tk.StringVar(value="1024")
        self.var_timeout_porta = tk.StringVar(value="300")
        self.var_monitorar = tk.BooleanVar(value=False)
        self.var_intervalo = tk.StringVar(value="5")

        def campo(texto, var, coluna, linha, largura=8, valores=None):
            ttk.Label(cfg, text=texto).grid(row=linha, column=coluna, sticky="w", padx=(0, 4), pady=3)
            if valores:
                w = ttk.Combobox(cfg, textvariable=var, values=valores, width=largura)
            else:
                w = ttk.Entry(cfg, textvariable=var, width=largura)
            w.grid(row=linha, column=coluna + 1, sticky="w", padx=(0, 18), pady=3)
            return w

        campo("Rede:", self.var_rede, 0, 0, 18, redes)
        campo("Timeout do ping (ms):", self.var_timeout_ping, 2, 0)
        campo("Portas de:", self.var_porta_ini, 4, 0, 6)
        campo("até:", self.var_porta_fim, 6, 0, 6)
        campo("Timeout da porta (ms):", self.var_timeout_porta, 2, 1)
        ttk.Checkbutton(cfg, text="Monitorar em tempo real, repetindo a cada",
                        variable=self.var_monitorar).grid(row=1, column=4, columnspan=3, sticky="w")
        intervalo = ttk.Frame(cfg)
        intervalo.grid(row=1, column=7, sticky="w")
        ttk.Entry(intervalo, textvariable=self.var_intervalo, width=5).pack(side="left")
        ttk.Label(intervalo, text=" segundos").pack(side="left")

        botoes = ttk.Frame(cfg)
        botoes.grid(row=0, column=8, rowspan=2, sticky="e", padx=(10, 0))
        cfg.columnconfigure(8, weight=1)
        self.bt_iniciar = ttk.Button(botoes, text="Iniciar varredura", command=self.iniciar)
        self.bt_iniciar.pack(fill="x", pady=2)
        self.bt_parar = ttk.Button(botoes, text="Parar", command=self.parar, state="disabled")
        self.bt_parar.pack(fill="x", pady=2)
        ttk.Button(botoes, text="Limpar tabela", command=self.limpar).pack(fill="x", pady=2)
        ttk.Button(botoes, text="Monitor local", command=lambda: abrir_monitor(self.janela)).pack(fill="x", pady=2)
        ttk.Button(botoes, text="Exportar CSV", command=self.exportar).pack(fill="x", pady=2)

        # --- progresso e resumo
        prog = ttk.Frame(self.janela, padding=(10, 0))
        prog.pack(fill="x")
        self.barra = ttk.Progressbar(prog, mode="determinate")
        self.barra.pack(fill="x", pady=(4, 2))
        linha = ttk.Frame(prog)
        linha.pack(fill="x")
        self.lbl_progresso = ttk.Label(linha, text="Pronto. Escolha a rede e clique em Iniciar varredura.")
        self.lbl_progresso.pack(side="left")
        self.lbl_resumo = ttk.Label(linha, text="", font=FONTE + ("bold",))
        self.lbl_resumo.pack(side="right")

        # --- tabela de dispositivos
        tab = ttk.Frame(self.janela, padding=(10, 6))
        tab.pack(fill="both", expand=True)
        colunas = [("ip", "IP", 110), ("mac", "MAC", 140), ("fabricante", "Fabricante", 150),
                   ("nome", "Nome", 150), ("tipo", "Tipo provável", 160),
                   ("status", "Status", 65), ("metodo", "Descoberto por", 140),
                   ("tempo", "Resposta", 70), ("ttl", "Último TTL (sistema provável)", 210),
                   ("portas", "Portas abertas", 230), ("visto", "Visto por último", 105),
                   ("obs", "Observações", 200)]
        self.colunas = colunas
        self.tabela = ttk.Treeview(tab, columns=[c[0] for c in colunas], show="headings")
        for chave, titulo, largura in colunas:
            self.tabela.heading(chave, text=titulo)
            self.tabela.column(chave, width=largura, minwidth=50, anchor="w", stretch=False)
        self.tabela.tag_configure("online", background="#dcfce7")    # verde
        self.tabela.tag_configure("arp", background="#fef9c3")       # amarelo
        self.tabela.tag_configure("offline", background="#fee2e2", foreground="#7f1d1d")  # vermelho
        self.tabela.tag_configure("conflito", background="#fed7aa", foreground="#7c2d12")  # laranja
        rolagem = ttk.Scrollbar(tab, orient="vertical", command=self.tabela.yview)
        rolagem_x = ttk.Scrollbar(tab, orient="horizontal", command=self.tabela.xview)
        self.tabela.configure(yscrollcommand=rolagem.set, xscrollcommand=rolagem_x.set)
        self.tabela.grid(row=0, column=0, sticky="nsew")
        rolagem.grid(row=0, column=1, sticky="ns")
        rolagem_x.grid(row=1, column=0, sticky="ew")
        tab.rowconfigure(0, weight=1)
        tab.columnconfigure(0, weight=1)

        legenda = ttk.Frame(self.janela, padding=(10, 0))
        legenda.pack(fill="x")
        for cor, texto in (("#dcfce7", "Online: respondeu ao ping"),
                           ("#fef9c3", "Online: bloqueia ping, achado por ARP"),
                           ("#fee2e2", "Offline: estava na rede e sumiu"),
                           ("#fed7aa", "Colisão de IP: o MAC deste IP mudou")):
            tk.Label(legenda, text="   ", bg=cor, relief="solid", bd=1).pack(side="left", padx=(0, 4))
            ttk.Label(legenda, text=texto).pack(side="left", padx=(0, 16))

        # --- log
        log = ttk.LabelFrame(self.janela, text="Registro", padding=4)
        log.pack(fill="x", padx=10, pady=(6, 10))
        self.txt_log = tk.Text(log, height=7, font=FONTE_LOG, state="disabled", wrap="none")
        self.txt_log.pack(fill="x")

    def log(self, msg: str):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("1.0", time.strftime("%H:%M:%S  ") + msg + "\n")
        self.txt_log.configure(state="disabled")

    # ------------------------------------------------------------------ botoes
    def _ler_numero(self, var, nome, minimo, maximo):
        try:
            n = int(var.get().strip())
        except ValueError:
            raise ValueError("%s deve ser um número inteiro." % nome)
        if not minimo <= n <= maximo:
            raise ValueError("%s deve estar entre %d e %d." % (nome, minimo, maximo))
        return n

    def _ler_parametros(self):
        """Le e valida os campos. Gera ValueError com a mensagem para o usuario."""
        p = {
            "rede": scanner.ler_rede(self.var_rede.get()),
            "timeout_ping": self._ler_numero(self.var_timeout_ping, "Timeout do ping", 100, 5000),
            "porta_ini": self._ler_numero(self.var_porta_ini, "Porta inicial", 1, 65535),
            "porta_fim": self._ler_numero(self.var_porta_fim, "Porta final", 1, 65535),
            "timeout_porta": self._ler_numero(self.var_timeout_porta, "Timeout da porta", 50, 5000),
            "intervalo": self._ler_numero(self.var_intervalo, "Intervalo do monitoramento", 5, 600),
        }
        if p["porta_ini"] > p["porta_fim"]:
            raise ValueError("A porta inicial deve ser menor ou igual à final.")
        return p

    def iniciar(self):
        if self.rodando:
            return
        try:
            self.params = self._ler_parametros()
        except ValueError as e:
            messagebox.showerror("Configuração inválida", str(e))
            return
        self.portas_feitas.clear()   # varredura manual: verifica as portas de todos de novo
        self.gateway = scanner.gateway_padrao()
        self._iniciar_rodada()

    def _iniciar_rodada(self):
        self.proxima_rodada = None
        self.rodando = True
        self.rodada += 1
        self.parar_evento.clear()
        self.bt_iniciar.configure(state="disabled")
        self.bt_parar.configure(state="normal")
        threading.Thread(target=self._trabalho, args=(dict(self.params),), daemon=True).start()

    def parar(self):
        self.parar_evento.set()
        self.lbl_progresso.configure(text="Parando...")
        if self.proxima_rodada:                      # cancela a proxima rodada agendada
            self.janela.after_cancel(self.proxima_rodada)
            self.proxima_rodada = None
            self._terminou(parado=True)

    def limpar(self):
        if self.rodando:
            return
        self.hosts.clear(); self.status.clear(); self.visto.clear(); self.faltas.clear()
        self.portas_feitas.clear(); self.conflitos.clear()
        self.tabela.delete(*self.tabela.get_children())
        self._atualizar_resumo()
        self.log("Tabela limpa")

    def exportar(self):
        """Salva a tabela IP/MAC (exatamente como esta na tela) num arquivo CSV.
        Usa ';' e UTF-8 com BOM para o Excel em portugues abrir direto, com acentos."""
        linhas = self.tabela.get_children()
        if not linhas:
            messagebox.showinfo("Exportar CSV", "A tabela está vazia. Faça uma varredura antes.")
            return
        caminho = filedialog.asksaveasfilename(
            title="Salvar inventário", defaultextension=".csv",
            filetypes=[("Planilha CSV", "*.csv")],
            initialfile=time.strftime("netprobe_%Y-%m-%d_%H-%M.csv"))
        if not caminho:
            return
        try:
            with open(caminho, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow([titulo for _, titulo, _ in self.colunas])
                for ip in linhas:
                    w.writerow(self.tabela.item(ip, "values"))
        except OSError as e:
            messagebox.showerror("Exportar CSV", "Não foi possível salvar: %s" % e)
            return
        self.log("Tabela exportada para %s (%d dispositivos)" % (caminho, len(linhas)))

    # ------------------------------------------------------------------ thread de varredura
    def _trabalho(self, p):
        """Roda FORA da tela (em outra thread), para a janela nao travar.
        Nao mexe na tela diretamente: manda mensagens pela fila."""
        try:
            total = sum(1 for _ in p["rede"].hosts())   # IPs testaveis (sem rede e broadcast)
            self.fila.put(("inicio", total, str(p["rede"])))
            t0 = time.time()
            achados = scanner.varrer_rede(
                p["rede"], p["timeout_ping"],
                ao_verificar=lambda ip, host: self.fila.put(("ip", ip, host)),
                parar=self.parar_evento.is_set)
            if self.parar_evento.is_set():
                self.fila.put(("fim", True)); return
            self.fila.put(("varredura_ok", [h.ip for h in achados], time.time() - t0))

            # Portas e nome: so de quem esta online e ainda nao foi verificado.
            # Varios aparelhos ao mesmo tempo, para nao esperar um terminar para comecar o outro.
            ja_feitos = set(self.portas_feitas)
            pendentes = [h for h in achados if h.ip not in ja_feitos]

            def nome_de(h):
                if self.parar_evento.is_set() or h.este_pc:
                    return
                nome = scanner.descobrir_nome(h.ip)
                if nome and not self.parar_evento.is_set():
                    self.fila.put(("nome", h.ip, nome))

            def portas_de(h):
                if self.parar_evento.is_set():
                    return
                self.fila.put(("portas_inicio", h.ip))
                portas = scanner.escanear_portas(h.ip, p["porta_ini"], p["porta_fim"],
                                                 p["timeout_porta"], parar=self.parar_evento.is_set)
                # Portas que entregam o tipo de aparelho (ex.: 62078 = iPhone), fora do intervalo
                extras = scanner.escanear_portas_identificacao(
                    h.ip, p["porta_ini"], p["porta_fim"], p["timeout_porta"], parar=self.parar_evento.is_set)
                if not self.parar_evento.is_set():
                    self.fila.put(("portas", h.ip, portas, extras))

            def servicos_mdns():
                # Uma pergunta para a REDE INTEIRA por rodada (pega iPhones, Macs, TVs...)
                resultado = scanner.descobrir_servicos_mdns(parar=self.parar_evento.is_set)
                if not self.parar_evento.is_set():
                    self.fila.put(("mdns", resultado))

            # Os nomes sao perguntados ao mesmo tempo que as portas sao testadas
            nomes = ThreadPoolExecutor(max_workers=16)
            try:
                nomes.submit(servicos_mdns)
                for h in pendentes:
                    nomes.submit(nome_de, h)
                with ThreadPoolExecutor(max_workers=HOSTS_EM_PARALELO) as pool:
                    list(pool.map(portas_de, pendentes))     # list() repassa erros das threads
            finally:
                nomes.shutdown(wait=not self.parar_evento.is_set(), cancel_futures=True)
            self.fila.put(("fim", self.parar_evento.is_set()))
        except Exception as e:  # nunca deixa a janela "presa" em rodando
            self.fila.put(("erro", "%s: %s" % (type(e).__name__, e)))

    # ------------------------------------------------------------------ fila -> tela
    def _processar_fila(self):
        """Roda a cada 100 ms na thread da tela e aplica as mensagens da varredura.

        Por que uma fila? O Tkinter so aceita ser mexido pela thread que criou a janela.
        A thread de varredura entao so ENVIA mensagens, e esta funcao as aplica na tela.
        Mensagens (sempre uma tupla, o 1o item diz o tipo):
          ("inicio", total, rede)        comecou uma rodada
          ("ip", ip, host ou None)       terminou um IP (None = vazio)
          ("varredura_ok", ips, segundos) terminou o ping+ARP de todos
          ("portas_inicio", ip)          comecou o teste de portas deste IP
          ("portas", ip, [portas], [extras]) terminou o teste de portas (extras = de identificacao)
          ("nome", ip, nome)             o aparelho disse o proprio nome
          ("mdns", {ip: InfoMdns})       servicos/nome/modelo anunciados na rede inteira
          ("fim", parado)                acabou a rodada (parado = clicaram em Parar)
          ("erro", texto)                deu erro inesperado na thread"""
        try:
            while True:
                msg = self.fila.get_nowait()
                tipo = msg[0]
                if tipo == "inicio":
                    self.barra.configure(maximum=msg[1], value=0)
                    self.feitos, self.total = 0, msg[1]
                    self.log("Rodada %d: varrendo %s (%d IPs)" % (self.rodada, msg[2], msg[1]))
                elif tipo == "ip":
                    self.feitos += 1
                    self.barra.configure(value=self.feitos)
                    self.lbl_progresso.configure(text="Verificando IPs: %d de %d" % (self.feitos, self.total))
                    if msg[2]:
                        self._host_encontrado(msg[2])
                    else:
                        self._registrar_falta(msg[1])
                elif tipo == "varredura_ok":
                    self._redesenhar_tudo()       # atualiza as observacoes (ex.: MAC repetido)
                    self.log("Varredura concluída em %.1f s: %d dispositivo(s) online" % (msg[2], len(msg[1])))
                    self.lbl_progresso.configure(text="Verificando portas...")
                elif tipo == "portas_inicio":
                    self._set_coluna(msg[1], "portas", "verificando...")
                    self.lbl_progresso.configure(text="Verificando portas de %s..." % msg[1])
                elif tipo == "portas":
                    ip, portas = msg[1], msg[2]
                    self.hosts[ip].portas = portas
                    self.hosts[ip].portas_extras = msg[3]
                    self.portas_feitas.add(ip)
                    self._desenhar_linha(ip)      # as portas tambem mudam o "tipo provavel"
                    if portas:
                        self.log("%s: portas abertas %s" % (ip, ", ".join(map(str, portas))))
                elif tipo == "nome":
                    ip, nome = msg[1], msg[2]
                    if not self.hosts[ip].nome:          # o nome amigavel do mDNS tem preferencia
                        self.hosts[ip].nome = nome
                        self.log("%s se identificou como \"%s\"" % (ip, nome))
                        self._desenhar_linha(ip)
                elif tipo == "mdns":
                    self._servicos_mdns(msg[1])
                elif tipo == "fim":
                    self._terminou(parado=msg[1])
                elif tipo == "erro":
                    self.log("ERRO: " + msg[1])
                    messagebox.showerror("Erro na varredura", msg[1])
                    self._terminou(parado=True)
        except queue.Empty:
            pass
        self.janela.after(100, self._processar_fila)

    def _terminou(self, parado: bool):
        self.rodando = False
        self.bt_iniciar.configure(state="normal")
        if parado:
            self.bt_parar.configure(state="disabled")
            self.lbl_progresso.configure(text="Parado.")
            self.log("Varredura interrompida pelo usuário")
            return
        if self.var_monitorar.get():
            seg = self.params["intervalo"]
            self.lbl_progresso.configure(text="Monitorando: próxima varredura em %d s" % seg)
            self.proxima_rodada = self.janela.after(seg * 1000, self._iniciar_rodada)
            self.bt_iniciar.configure(state="disabled")   # Parar continua ativo
        else:
            self.bt_parar.configure(state="disabled")
            self.lbl_progresso.configure(text="Concluído.")

    # ------------------------------------------------------------------ tabela
    def _host_encontrado(self, h: scanner.Host):
        # A cada rodada chega um Host NOVO para o mesmo IP. Aqui juntamos com o que ja se
        # sabia dele: o que a rodada atual nao trouxe (portas, MAC, TTL, nome) vem da anterior.
        novo = h.ip not in self.hosts
        antes = self.status.get(h.ip)
        if not novo:
            anterior = self.hosts[h.ip]
            h.portas = anterior.portas           # mantem as portas ja descobertas
            h.mac = h.mac or anterior.mac        # se o ARP falhou agora, mantem o MAC anterior
            if anterior.mac and h.mac != anterior.mac:
                self._mac_mudou(h.ip, anterior.mac, h.mac, estava_offline=(antes == "offline"))
            else:                                # mesmo aparelho: mantem o que ja foi descoberto
                h.ttl = h.ttl or anterior.ttl
                h.nome = h.nome or anterior.nome
                h.servicos = h.servicos or anterior.servicos
                h.modelo = h.modelo or anterior.modelo
                h.portas_extras = h.portas_extras or anterior.portas_extras
        self.hosts[h.ip] = h
        self.status[h.ip] = "arp" if h.metodo == "ARP" else "online"
        self.visto[h.ip] = time.strftime("%H:%M:%S")
        self.faltas[h.ip] = 0
        if novo:
            if h.metodo == "ARP":
                self.log("%s encontrado por ARP (não respondeu ao ping, MAC %s)" % (h.ip, h.mac))
            else:
                self.log("%s respondeu ao ping em %s" % (h.ip, scanner.texto_tempo(h.tempo_ms)))
        elif antes == "offline":
            self.log("%s voltou a ficar ONLINE" % h.ip)
        self._desenhar_linha(h.ip)

    def _servicos_mdns(self, resultado):
        """Aplica o que cada aparelho anunciou por mDNS (servicos, nome amigavel, modelo)."""
        for ip, info in resultado.items():
            h = self.hosts.get(ip)
            if h is None or h.este_pc or self.status.get(ip) == "offline":
                continue
            antes = (h.nome, h.modelo, set(h.servicos))
            scanner.aplicar_mdns(h, info)
            if (h.nome, h.modelo, h.servicos) != antes:
                detalhes = [x for x in (h.nome and '"%s"' % h.nome, h.modelo and "modelo " + h.modelo) if x]
                self.log("%s anunciou por mDNS: %s" % (
                    ip, ", ".join(detalhes + [", ".join(sorted(h.servicos))])))
                self._desenhar_linha(ip)

    def _mac_mudou(self, ip, mac_antigo, mac_novo, estava_offline):
        """Deteccao de COLISAO DE IP: o mesmo IP respondeu com outro MAC.
        - Se o IP estava offline: normal, o roteador (DHCP) deu o IP para outro aparelho.
        - Se estava online: dois aparelhos disputam o mesmo IP (IP fixo repetido)
          ou alguem esta respondendo ARP no lugar do outro (ARP spoofing)."""
        self.portas_feitas.discard(ip)           # outro aparelho: verifica as portas de novo
        if estava_offline:
            self.conflitos.pop(ip, None)
            self.log("%s agora é outro aparelho: MAC %s -> %s (o roteador reaproveitou o IP)"
                     % (ip, mac_antigo, mac_novo))
        else:
            self.conflitos[ip] = mac_antigo
            self.log("ALERTA: possível COLISÃO DE IP em %s: MAC %s -> %s. Dois aparelhos com o "
                     "mesmo IP, ou ARP spoofing." % (ip, mac_antigo, mac_novo))

    def _registrar_falta(self, ip: str):
        """Conta uma falta assim que o ping e o ARP deste IP terminam sem resposta."""
        if ip not in self.hosts or self.status.get(ip) == "offline":
            return
        self.faltas[ip] = self.faltas.get(ip, 0) + 1
        if self.faltas[ip] == 1:
            self.log("%s não respondeu nesta rodada (será OFFLINE se faltar de novo)" % ip)
            return
        self.status[ip] = "offline"
        self.portas_feitas.discard(ip)
        self.log("%s ficou OFFLINE" % ip)
        self._desenhar_linha(ip)

    def _desenhar_linha(self, ip: str):
        h, st = self.hosts[ip], self.status[ip]
        nome_status = {"online": "Online", "arp": "Online", "offline": "Offline"}[st]
        if h.este_pc:
            metodo = "Este computador"
        elif h.metodo == "ARP":
            metodo = "ARP (bloqueia ping)"
        else:
            metodo = "Ping (ICMP)"
        tempo = scanner.texto_tempo(h.tempo_ms) if st != "offline" else "-"
        if ip in self.portas_feitas:
            portas = self._texto_portas(h.portas)
        elif st == "offline":
            portas = "-"
        else:
            portas = "aguardando..."
        ttl = "Sem medição"
        if h.ttl is not None:
            ttl = "%d (%s)" % (h.ttl, scanner.palpite_sistema(h.ttl))
        elif h.metodo == "ARP":
            ttl = "Sem TTL (só ARP)"
        valores = (ip, h.mac or "desconhecido", scanner.texto_fabricante(h.mac),
                   h.nome or "-", scanner.palpite_tipo(h, self.gateway), nome_status,
                   metodo, tempo, ttl, portas, self.visto.get(ip, "-"), self._observacoes(ip))
        tag = "conflito" if ip in self.conflitos and st != "offline" else st
        if self.tabela.exists(ip):
            self.tabela.item(ip, values=valores, tags=(tag,))
        else:
            self.tabela.insert("", "end", iid=ip, values=valores, tags=(tag,))
            self._ordenar()
        self._atualizar_resumo()

    def _redesenhar_tudo(self):
        for ip in self.hosts:
            self._desenhar_linha(ip)

    def _observacoes(self, ip: str) -> str:
        """Avisos sobre a vinculacao IP/MAC deste aparelho."""
        h, obs = self.hosts[ip], []
        if ip in self.conflitos:
            obs.append("COLISÃO DE IP (MAC antes: %s)" % self.conflitos[ip])
        if h.mac and self.status[ip] != "offline":
            # O mesmo MAC em varios IPs: repetidor Wi-Fi, aparelho com 2 IPs ou ARP spoofing
            outros = [o for o, x in self.hosts.items()
                      if o != ip and x.mac == h.mac and self.status.get(o) != "offline"]
            if outros:
                obs.append("mesmo MAC que " + ", ".join(sorted(outros, key=ipaddress.ip_address)))
        if h.modelo:
            obs.append("modelo " + h.modelo)
        if h.portas_extras:
            # Portas fora do intervalo escolhido, testadas so para identificar o aparelho
            obs.append("porta de identificação: " + ", ".join(scanner.nome_porta(p) for p in h.portas_extras))
        return "; ".join(obs)

    def _set_coluna(self, ip, coluna, valor):
        if self.tabela.exists(ip):
            self.tabela.set(ip, coluna, valor)

    def _ordenar(self):
        ips = sorted(self.tabela.get_children(), key=ipaddress.ip_address)
        for i, ip in enumerate(ips):
            self.tabela.move(ip, "", i)

    @staticmethod
    def _texto_portas(portas):
        return ", ".join(scanner.nome_porta(p) for p in portas) if portas else "nenhuma no intervalo"

    def _atualizar_resumo(self):
        v = list(self.status.values())
        texto = "Online: %d   (só por ARP: %d)   Offline: %d" % (
            v.count("online") + v.count("arp"), v.count("arp"), v.count("offline"))
        if self.conflitos:
            texto += "   Colisões de IP: %d" % len(self.conflitos)
        self.lbl_resumo.configure(text=texto)


if __name__ == "__main__":
    raiz = tk.Tk()
    NetProbeApp(raiz)
    raiz.mainloop()
