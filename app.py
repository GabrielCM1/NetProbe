"""
NetProbe Wi-Fi - INTERFACE (janela).

Abre uma janela com:
  - campos para escolher a rede, os timeouts e o intervalo de portas;
  - uma tabela que vai se preenchendo em TEMPO REAL com IP, MAC, status e portas;
  - modo "monitorar", que repete a varredura sozinho e marca quem saiu da rede como OFFLINE;
  - alerta de COLISAO DE IP quando o MAC de um IP muda entre uma rodada e outra;
  - exportacao da tabela IP/MAC para CSV.

Toda a parte de rede esta em scanner.py. Este arquivo so cuida da tela.
Para rodar:  python app.py
"""
# ==========================================================================
# MAPA DESTE ARQUIVO (versão comentada, para estudo)
# ==========================================================================
# O programa tem DUAS threads trabalhando ao mesmo tempo:
#
#   THREAD DA TELA (principal)              THREAD DE VARREDURA (_trabalho)
#   -------------------------               -------------------------------
#   clique em "Iniciar varredura"
#     iniciar()  -> valida os campos
#     _iniciar_rodada() --- cria --->       _trabalho():
#                                             scanner.varrer_rede()   (ping + ARP)
#                                               cada IP terminado -> fila.put("ip")
#                                             fila.put("varredura_ok")
#                                             scanner.escanear_portas() de cada online
#                                               -> fila.put("portas")
#                                             fila.put("fim")
#   _processar_fila()  <--- lê a fila a cada 100 ms ---
#     "ip"           -> _host_encontrado() -> _desenhar_linha()
#     "varredura_ok" -> _marcar_offline()  (quem sumiu)
#     "portas"       -> escreve as portas na linha
#     "fim"          -> _terminou() -> se "Monitorar": agenda a próxima rodada
#
# Por que duas threads e uma fila? O Tkinter só aceita ser mexido pela thread que
# criou a janela. Se a varredura (que leva ~10 s) rodasse na thread da tela, a
# janela congelaria. Então a varredura roda em outra thread e só MANDA RECADOS
# pela fila; quem mexe na tela é sempre a thread principal.
#
# Ordem das seções: constantes -> __init__ (estado) -> _montar_tela (widgets)
# -> botões (iniciar, parar, limpar, exportar) -> _trabalho (varredura)
# -> _processar_fila (recados -> tela) -> tabela (linhas, offline, colisão)
# ==========================================================================
import csv                     # escrever o arquivo CSV (exportar)
import ipaddress               # ordenar a tabela por IP corretamente (.2 antes de .10)
import queue                   # a fila de recados entre as duas threads
import threading               # criar a thread de varredura e a "bandeira" de parar
import time                    # hora atual para o log e para "visto por último"
import tkinter as tk           # a biblioteca de janelas que já vem com o Python
from concurrent.futures import ThreadPoolExecutor   # portas de vários aparelhos ao mesmo tempo
from tkinter import filedialog, messagebox, ttk     # janela "Salvar como", avisos e widgets

import scanner                 # toda a parte de rede (o outro arquivo)

# Fontes comuns em cada sistema (se faltar alguma, o Tk usa a padrão)
FONTE = ("Segoe UI", 10) if scanner.WINDOWS else ("DejaVu Sans", 10)
FONTE_LOG = ("Consolas", 9) if scanner.WINDOWS else ("DejaVu Sans Mono", 9)

# Quantos aparelhos têm as portas verificadas ao mesmo tempo (cada um usa 200 conexões)
HOSTS_EM_PARALELO = 3


class NetProbeApp:
    # ------------------------------------------------------------------ início
    def __init__(self, janela: tk.Tk):
        # Passo 1: configura a janela.
        self.janela = janela
        janela.title("NetProbe Wi-Fi")
        janela.geometry("1400x700")
        janela.minsize(900, 560)

        # Passo 2: o "estado" do programa. Tudo o que ele lembra entre uma rodada e outra.
        # Os dicionários usam o IP como chave.
        self.hosts = {}            # ip -> scanner.Host (todos que já apareceram)
        self.status = {}           # ip -> "online" | "arp" | "offline"
        self.visto = {}            # ip -> hora em que foi visto pela última vez
        self.faltas = {}           # ip -> quantas rodadas seguidas ele não apareceu
        self.conflitos = {}        # ip -> MAC antigo, quando o MAC do IP mudou (colisão de IP)
        self.portas_feitas = set() # ips que já tiveram as portas verificadas
        self.fila = queue.Queue()  # recados da thread de varredura para a tela
        self.parar_evento = threading.Event()   # "bandeira": levantada quando clicam em Parar
        self.rodando = False       # True enquanto uma rodada está em andamento
        self.proxima_rodada = None # agendamento do modo monitorar (para poder cancelar)
        self.rodada = 0            # contador de rodadas, só para o log

        # Passo 3: desenha a janela e começa a "escutar" a fila (a cada 100 ms, para sempre).
        self._montar_tela()
        self._processar_fila()     # começa a "escutar" a fila

    # ------------------------------------------------------------------ tela
    def _montar_tela(self):
        # Esta função só CRIA os componentes visuais. Não tem lógica de rede.
        # Estrutura de cima para baixo: Configuração -> barra de progresso ->
        # tabela -> legenda de cores -> Registro (log).
        estilo = ttk.Style()
        estilo.configure("Treeview", rowheight=24, font=FONTE)
        estilo.configure("Treeview.Heading", font=FONTE + ("bold",))

        # --- quadro "Configuração" (campos e botões)
        cfg = ttk.LabelFrame(self.janela, text="Configuração", padding=10)
        cfg.pack(fill="x", padx=10, pady=(10, 5))

        # Variáveis ligadas aos campos: quando o usuário digita, o valor muda aqui.
        # Os valores iniciais são os padrões que aparecem ao abrir o programa.
        redes = scanner.redes_sugeridas() or ["192.168.0.0/24"]
        self.var_rede = tk.StringVar(value=redes[0])
        self.var_timeout_ping = tk.StringVar(value="500")
        self.var_porta_ini = tk.StringVar(value="1")
        self.var_porta_fim = tk.StringVar(value="1024")
        self.var_timeout_porta = tk.StringVar(value="300")
        self.var_monitorar = tk.BooleanVar(value=False)
        self.var_intervalo = tk.StringVar(value="20")

        # Função auxiliar: cria um rótulo + campo numa posição da grade (linha, coluna).
        # Se receber "valores", vira uma lista suspensa (Combobox) em vez de campo simples.
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

        # Botões. "command=" diz qual função roda no clique.
        botoes = ttk.Frame(cfg)
        botoes.grid(row=0, column=8, rowspan=2, sticky="e", padx=(10, 0))
        cfg.columnconfigure(8, weight=1)
        self.bt_iniciar = ttk.Button(botoes, text="Iniciar varredura", command=self.iniciar)
        self.bt_iniciar.pack(fill="x", pady=2)
        self.bt_parar = ttk.Button(botoes, text="Parar", command=self.parar, state="disabled")
        self.bt_parar.pack(fill="x", pady=2)
        ttk.Button(botoes, text="Limpar tabela", command=self.limpar).pack(fill="x", pady=2)
        ttk.Button(botoes, text="Exportar CSV", command=self.exportar).pack(fill="x", pady=2)

        # --- barra de progresso e resumo (Online / só por ARP / Offline)
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

        # --- tabela de dispositivos (Treeview)
        tab = ttk.Frame(self.janela, padding=(10, 6))
        tab.pack(fill="both", expand=True)
        # Cada coluna: (nome interno, título na tela, largura em pixels).
        # A ordem aqui é a mesma ordem dos valores montados em _desenhar_linha().
        colunas = [("ip", "IP", 110), ("mac", "MAC", 140), ("fabricante", "Fabricante", 150),
                   ("status", "Status", 65), ("metodo", "Descoberto por", 140),
                   ("tempo", "Resposta", 70), ("ttl", "TTL (sistema)", 170),
                   ("portas", "Portas abertas", 230), ("visto", "Visto por último", 105),
                   ("obs", "Observações", 200)]
        self.colunas = colunas
        self.tabela = ttk.Treeview(tab, columns=[c[0] for c in colunas], show="headings")
        for chave, titulo, largura in colunas:
            self.tabela.heading(chave, text=titulo)
            self.tabela.column(chave, width=largura, anchor="w", stretch=chave in ("portas", "obs"))
        # "Tags" = estilos de linha. Cada linha recebe uma tag conforme o status,
        # e a tag define a cor de fundo.
        self.tabela.tag_configure("online", background="#dcfce7")    # verde
        self.tabela.tag_configure("arp", background="#fef9c3")       # amarelo
        self.tabela.tag_configure("offline", background="#fee2e2", foreground="#7f1d1d")  # vermelho
        self.tabela.tag_configure("conflito", background="#fed7aa", foreground="#7c2d12")  # laranja
        rolagem = ttk.Scrollbar(tab, orient="vertical", command=self.tabela.yview)
        self.tabela.configure(yscrollcommand=rolagem.set)
        self.tabela.pack(side="left", fill="both", expand=True)
        rolagem.pack(side="right", fill="y")

        # --- legenda das cores
        legenda = ttk.Frame(self.janela, padding=(10, 0))
        legenda.pack(fill="x")
        for cor, texto in (("#dcfce7", "Online: respondeu ao ping"),
                           ("#fef9c3", "Online: bloqueia ping, achado por ARP"),
                           ("#fee2e2", "Offline: estava na rede e sumiu"),
                           ("#fed7aa", "Colisão de IP: o MAC deste IP mudou")):
            tk.Label(legenda, text="   ", bg=cor, relief="solid", bd=1).pack(side="left", padx=(0, 4))
            ttk.Label(legenda, text=texto).pack(side="left", padx=(0, 16))

        # --- "Registro" (log de eventos, o mais recente em cima)
        log = ttk.LabelFrame(self.janela, text="Registro", padding=4)
        log.pack(fill="x", padx=10, pady=(6, 10))
        self.txt_log = tk.Text(log, height=7, font=FONTE_LOG, state="disabled", wrap="none")
        self.txt_log.pack(fill="x")

    def log(self, msg: str):
        # O campo fica "disabled" para o usuário não digitar nele. Para escrever,
        # habilita, insere a linha NO TOPO ("1.0" = linha 1, coluna 0) e desabilita de novo.
        self.txt_log.configure(state="normal")
        self.txt_log.insert("1.0", time.strftime("%H:%M:%S  ") + msg + "\n")
        self.txt_log.configure(state="disabled")

    # ------------------------------------------------------------------ botões
    def _ler_numero(self, var, nome, minimo, maximo):
        # Converte o texto do campo em número inteiro e confere os limites.
        # Se der errado, gera ValueError com uma mensagem para mostrar ao usuário.
        try:
            n = int(var.get().strip())
        except ValueError:
            raise ValueError("%s deve ser um número inteiro." % nome)
        if not minimo <= n <= maximo:
            raise ValueError("%s deve estar entre %d e %d." % (nome, minimo, maximo))
        return n

    def _ler_parametros(self):
        """Le e valida os campos. Gera ValueError com a mensagem para o usuario."""
        # Lê TODOS os campos de uma vez. Se qualquer um estiver errado, para no primeiro
        # erro. Os limites evitam valores absurdos (ex.: timeout de 1 hora).
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
        # Roda quando clicam em "Iniciar varredura".
        # Passo 1: se já está rodando, ignora o clique.
        if self.rodando:
            return
        # Passo 2: lê e valida os campos. Se algo estiver errado, mostra a mensagem e para.
        try:
            self.params = self._ler_parametros()
        except ValueError as e:
            messagebox.showerror("Configuração inválida", str(e))
            return
        # Passo 3: varredura manual = verificar as portas de todo mundo de novo.
        self.portas_feitas.clear()   # varredura manual: verifica as portas de todos de novo
        # Passo 4: começa a rodada.
        self._iniciar_rodada()

    def _iniciar_rodada(self):
        # Chamada pelo botão Iniciar e, no modo Monitorar, de novo a cada N segundos.
        self.proxima_rodada = None
        self.rodando = True
        self.rodada += 1
        self.parar_evento.clear()                 # abaixa a bandeira de parar
        self.bt_iniciar.configure(state="disabled")
        self.bt_parar.configure(state="normal")
        # Cria a THREAD DE VARREDURA, que vai rodar _trabalho() em paralelo com a tela.
        # daemon=True: se fecharem a janela, a thread morre junto.
        # dict(self.params) entrega uma CÓPIA dos parâmetros, para a thread não ser
        # afetada se o usuário mexer nos campos durante a varredura.
        threading.Thread(target=self._trabalho, args=(dict(self.params),), daemon=True).start()

    def parar(self):
        # Roda quando clicam em "Parar".
        # Passo 1: levanta a bandeira. A thread de varredura confere essa bandeira
        # a cada 0,2 s (em scanner.em_paralelo) e para sozinha.
        self.parar_evento.set()
        self.lbl_progresso.configure(text="Parando...")
        # Passo 2: se estava no intervalo do modo Monitorar (sem rodada em andamento),
        # cancela a próxima rodada agendada e encerra na hora.
        if self.proxima_rodada:                      # cancela a próxima rodada agendada
            self.janela.after_cancel(self.proxima_rodada)
            self.proxima_rodada = None
            self._terminou(parado=True)

    def limpar(self):
        # Esquece tudo (aparelhos, faltas, colisões) e apaga a tabela.
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
        # Passo 1: se a tabela estiver vazia, avisa e para.
        linhas = self.tabela.get_children()
        if not linhas:
            messagebox.showinfo("Exportar CSV", "A tabela está vazia. Faça uma varredura antes.")
            return
        # Passo 2: abre a janela "Salvar como", com um nome sugerido com data e hora.
        caminho = filedialog.asksaveasfilename(
            title="Salvar inventário", defaultextension=".csv",
            filetypes=[("Planilha CSV", "*.csv")],
            initialfile=time.strftime("netprobe_%Y-%m-%d_%H-%M.csv"))
        if not caminho:
            return                                # o usuário cancelou
        # Passo 3: escreve o arquivo. 1ª linha = títulos das colunas; depois, uma linha
        # por aparelho, com os mesmos valores que aparecem na tela.
        # ";" porque o Excel em português usa a vírgula como decimal;
        # "utf-8-sig" coloca uma marca no início para o Excel entender os acentos.
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
        # IMPORTANTE: daqui para baixo NADA mexe na janela. Tudo vira um recado na fila
        # (self.fila.put(...)), que a thread da tela aplica em _processar_fila().
        try:
            # Passo 1: avisa quantos IPs serão testados (para a barra de progresso).
            # Uma /24 tem 256 endereços; tirando o da rede e o de broadcast, 254.
            total = p["rede"].num_addresses - 2 if p["rede"].prefixlen < 31 else p["rede"].num_addresses
            self.fila.put(("inicio", total, str(p["rede"])))
            t0 = time.time()
            # Passo 2: PING + ARP em todos os IPs (scanner.varrer_rede).
            # A cada IP terminado, a função lambda manda um recado ("ip", ip, host).
            # É isso que faz a tabela se preencher enquanto a varredura acontece.
            achados = scanner.varrer_rede(
                p["rede"], p["timeout_ping"],
                ao_verificar=lambda ip, host: self.fila.put(("ip", ip, host)),
                parar=self.parar_evento.is_set)
            # Passo 3: se clicaram em Parar no meio, encerra aqui.
            if self.parar_evento.is_set():
                self.fila.put(("fim", True)); return
            # Passo 4: avisa que o ping+ARP acabou, com a lista de quem está online.
            # A tela usa isso para descobrir quem SUMIU (offline).
            self.fila.put(("varredura_ok", [h.ip for h in achados], time.time() - t0))

            # Portas: só de quem está online e ainda não foi verificado.
            # Vários aparelhos ao mesmo tempo, para não esperar um terminar para começar o outro.
            # Passo 5: separa quem ainda precisa ter as portas testadas.
            # (No modo Monitorar, quem já foi testado é pulado, para a rodada ser rápida.)
            ja_feitos = set(self.portas_feitas)
            pendentes = [h for h in achados if h.ip not in ja_feitos]

            # O que fazer com cada aparelho: avisa que começou, testa as portas
            # (scanner.escanear_portas) e manda o resultado pela fila.
            def portas_de(h):
                if self.parar_evento.is_set():
                    return
                self.fila.put(("portas_inicio", h.ip))
                portas = scanner.escanear_portas(h.ip, p["porta_ini"], p["porta_fim"],
                                                 p["timeout_porta"], parar=self.parar_evento.is_set)
                if not self.parar_evento.is_set():
                    self.fila.put(("portas", h.ip, portas))

            # Passo 6: roda portas_de() para 3 aparelhos ao mesmo tempo.
            with ThreadPoolExecutor(max_workers=HOSTS_EM_PARALELO) as pool:
                list(pool.map(portas_de, pendentes))     # list() repassa erros das threads
            # Passo 7: avisa que a rodada acabou (e se foi interrompida ou não).
            self.fila.put(("fim", self.parar_evento.is_set()))
        except Exception as e:  # nunca deixa a janela "presa" em rodando
            # Qualquer erro inesperado vira um recado, para a tela mostrar e destravar.
            self.fila.put(("erro", "%s: %s" % (type(e).__name__, e)))

    # ------------------------------------------------------------------ fila -> tela
    def _processar_fila(self):
        """Roda a cada 100 ms na thread da tela e aplica as mensagens da varredura."""
        # Recados possíveis (o 1º item diz o tipo):
        #   ("inicio", total, rede)          começou uma rodada
        #   ("ip", ip, host ou None)         terminou um IP (None = IP vazio)
        #   ("varredura_ok", ips, segundos)  acabou o ping+ARP de todos
        #   ("portas_inicio", ip)            começou o teste de portas deste IP
        #   ("portas", ip, [portas])         acabou o teste de portas deste IP
        #   ("fim", parado)                  acabou a rodada
        #   ("erro", texto)                  deu erro inesperado na thread
        try:
            # Passo 1: pega TODOS os recados que chegaram desde a última vez.
            # get_nowait() não espera: se a fila estiver vazia, gera queue.Empty
            # e o laço termina.
            while True:
                msg = self.fila.get_nowait()
                tipo = msg[0]
                if tipo == "inicio":
                    # Zera a barra de progresso.
                    self.barra.configure(maximum=msg[1], value=0)
                    self.feitos, self.total = 0, msg[1]
                    self.log("Rodada %d: varrendo %s (%d IPs)" % (self.rodada, msg[2], msg[1]))
                elif tipo == "ip":
                    # Avança a barra; se o IP tem aparelho, atualiza a tabela.
                    self.feitos += 1
                    self.barra.configure(value=self.feitos)
                    self.lbl_progresso.configure(text="Verificando IPs: %d de %d" % (self.feitos, self.total))
                    if msg[2]:
                        self._host_encontrado(msg[2])
                elif tipo == "varredura_ok":
                    # Confere quem sumiu e redesenha as observações de todos.
                    self._marcar_offline(set(msg[1]))
                    self._redesenhar_tudo()       # atualiza as observações (ex.: MAC repetido)
                    self.log("Varredura concluída em %.1f s: %d dispositivo(s) online" % (msg[2], len(msg[1])))
                    self.lbl_progresso.configure(text="Verificando portas...")
                elif tipo == "portas_inicio":
                    self._set_coluna(msg[1], "portas", "verificando...")
                    self.lbl_progresso.configure(text="Verificando portas de %s..." % msg[1])
                elif tipo == "portas":
                    # Guarda as portas no Host e escreve na coluna.
                    ip, portas = msg[1], msg[2]
                    self.hosts[ip].portas = portas
                    self.portas_feitas.add(ip)
                    self._set_coluna(ip, "portas", self._texto_portas(portas))
                    if portas:
                        self.log("%s: portas abertas %s" % (ip, ", ".join(map(str, portas))))
                elif tipo == "fim":
                    self._terminou(parado=msg[1])
                elif tipo == "erro":
                    self.log("ERRO: " + msg[1])
                    messagebox.showerror("Erro na varredura", msg[1])
                    self._terminou(parado=True)
        except queue.Empty:
            pass                                  # fila vazia: nada mais para fazer agora
        # Passo 2: agenda a si mesma de novo daqui a 100 ms. É um "laço" que nunca para,
        # mas sem travar a janela (o Tkinter continua respondendo entre as chamadas).
        self.janela.after(100, self._processar_fila)

    def _terminou(self, parado: bool):
        # Fim de uma rodada.
        self.rodando = False
        self.bt_iniciar.configure(state="normal")
        # Caso 1: foi interrompida pelo botão Parar.
        if parado:
            self.bt_parar.configure(state="disabled")
            self.lbl_progresso.configure(text="Parado.")
            self.log("Varredura interrompida pelo usuário")
            return
        # Caso 2: modo Monitorar ligado -> agenda a próxima rodada daqui a N segundos.
        # janela.after(ms, função) chama a função depois desse tempo, sem travar a tela.
        if self.var_monitorar.get():
            seg = self.params["intervalo"]
            self.lbl_progresso.configure(text="Monitorando: próxima varredura em %d s" % seg)
            self.proxima_rodada = self.janela.after(seg * 1000, self._iniciar_rodada)
            self.bt_iniciar.configure(state="disabled")   # Parar continua ativo
        # Caso 3: varredura única terminou normalmente.
        else:
            self.bt_parar.configure(state="disabled")
            self.lbl_progresso.configure(text="Concluído.")

    # ------------------------------------------------------------------ tabela
    def _host_encontrado(self, h: scanner.Host):
        # Chamado para cada aparelho que respondeu (ping ou ARP) nesta rodada.
        # A cada rodada chega um Host NOVO para o mesmo IP; aqui juntamos com o que
        # já sabíamos dele.
        novo = h.ip not in self.hosts            # é a primeira vez que vemos este IP?
        antes = self.status.get(h.ip)            # status na rodada anterior
        if not novo:
            # Passo 1: completa com o que a rodada atual não trouxe.
            anterior = self.hosts[h.ip]
            h.portas = anterior.portas           # mantém as portas já descobertas
            h.mac = h.mac or anterior.mac        # se o ARP falhou agora, mantém o MAC anterior
            h.ttl = h.ttl or anterior.ttl        # rodada achada só por ARP não tem TTL
            # Passo 2: DETECÇÃO DE COLISÃO DE IP. O mesmo IP respondeu com OUTRO MAC?
            if anterior.mac and h.mac != anterior.mac:
                self._mac_mudou(h.ip, anterior.mac, h.mac, estava_offline=(antes == "offline"))
        # Passo 3: atualiza o estado: guarda o Host, o status, a hora e zera as faltas.
        self.hosts[h.ip] = h
        self.status[h.ip] = "arp" if h.metodo == "ARP" else "online"
        self.visto[h.ip] = time.strftime("%H:%M:%S")
        self.faltas[h.ip] = 0
        # Passo 4: escreve no Registro só o que é novidade.
        if novo:
            if h.metodo == "ARP":
                self.log("%s encontrado por ARP (não respondeu ao ping, MAC %s)" % (h.ip, h.mac))
            else:
                self.log("%s respondeu ao ping em %s" % (h.ip, scanner.texto_tempo(h.tempo_ms)))
        elif antes == "offline":
            self.log("%s voltou a ficar ONLINE" % h.ip)
        # Passo 5: desenha (ou redesenha) a linha deste IP na tabela.
        self._desenhar_linha(h.ip)

    def _mac_mudou(self, ip, mac_antigo, mac_novo, estava_offline):
        """Deteccao de COLISAO DE IP: o mesmo IP respondeu com outro MAC.
        - Se o IP estava offline: normal, o roteador (DHCP) deu o IP para outro aparelho.
        - Se estava online: dois aparelhos disputam o mesmo IP (IP fixo repetido)
          ou alguem esta respondendo ARP no lugar do outro (ARP spoofing)."""
        self.portas_feitas.discard(ip)           # outro aparelho: verifica as portas de novo
        if estava_offline:
            # Caso normal: tira um eventual alerta antigo e só registra no log.
            self.conflitos.pop(ip, None)
            self.log("%s agora é outro aparelho: MAC %s -> %s (o roteador reaproveitou o IP)"
                     % (ip, mac_antigo, mac_novo))
        else:
            # Caso suspeito: marca o conflito. A linha fica laranja em _desenhar_linha().
            self.conflitos[ip] = mac_antigo
            self.log("ALERTA: possível COLISÃO DE IP em %s: MAC %s -> %s. Dois aparelhos com o "
                     "mesmo IP, ou ARP spoofing." % (ip, mac_antigo, mac_novo))

    def _marcar_offline(self, online_agora: set):
        """Quem ja tinha aparecido e nao respondeu nesta rodada.
        So vira OFFLINE depois de faltar em 2 rodadas seguidas: celulares em modo
        economia as vezes deixam de responder uma vez, e a tela ficaria piscando."""
        # Percorre TODOS os aparelhos que já apareceram alguma vez.
        for ip in self.hosts:
            # Respondeu nesta rodada, ou já está offline: nada a fazer.
            if ip in online_agora or self.status.get(ip) == "offline":
                continue
            # Não respondeu: conta mais uma falta.
            self.faltas[ip] = self.faltas.get(ip, 0) + 1
            if self.faltas[ip] == 1:
                # 1ª falta: só avisa (pode ser um celular "cochilando").
                self.log("%s não respondeu nesta rodada (será OFFLINE se faltar de novo)" % ip)
            else:
                # 2ª falta seguida: agora sim, OFFLINE (linha vermelha).
                self.status[ip] = "offline"
                self.portas_feitas.discard(ip)    # quando voltar, verifica as portas de novo
                self.log("%s ficou OFFLINE" % ip)
                self._desenhar_linha(ip)
        self._atualizar_resumo()

    def _desenhar_linha(self, ip: str):
        # Monta o texto de cada coluna para este IP e põe na tabela.
        h, st = self.hosts[ip], self.status[ip]
        # Passo 1: calcula o texto de cada coluna.
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
        ttl = "%d (%s)" % (h.ttl, scanner.palpite_sistema(h.ttl)) if h.ttl else "-"
        # Passo 2: junta tudo na MESMA ordem das colunas definidas em _montar_tela().
        valores = (ip, h.mac or "desconhecido", scanner.fabricante(h.mac) or "-", nome_status,
                   metodo, tempo, ttl, portas, self.visto.get(ip, "-"), self._observacoes(ip))
        # Passo 3: escolhe a cor. Colisão (laranja) tem prioridade, exceto se está offline.
        tag = "conflito" if ip in self.conflitos and st != "offline" else st
        # Passo 4: se a linha já existe, atualiza; se não, cria e reordena a tabela por IP.
        # O próprio IP é usado como identificador da linha (iid).
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
        # Aviso 1: houve colisão de IP neste endereço.
        if ip in self.conflitos:
            obs.append("COLISÃO DE IP (MAC antes: %s)" % self.conflitos[ip])
        # Aviso 2: o mesmo MAC aparece em outro IP online.
        if h.mac and self.status[ip] != "offline":
            # O mesmo MAC em vários IPs: repetidor Wi-Fi, aparelho com 2 IPs ou ARP spoofing
            outros = [o for o, x in self.hosts.items()
                      if o != ip and x.mac == h.mac and self.status.get(o) != "offline"]
            if outros:
                obs.append("mesmo MAC que " + ", ".join(sorted(outros, key=ipaddress.ip_address)))
        # Aviso 3: MAC aleatório (celulares, por privacidade).
        if scanner.mac_aleatorio(h.mac):
            obs.append("MAC aleatório (privacidade)")
        return "; ".join(obs)

    def _set_coluna(self, ip, coluna, valor):
        # Muda só uma coluna de uma linha (usado para "verificando..." e para as portas).
        if self.tabela.exists(ip):
            self.tabela.set(ip, coluna, valor)

    def _ordenar(self):
        # Ordena as linhas por IP de verdade (ip_address), e não como texto.
        # Como texto, "192.168.15.10" viria antes de "192.168.15.2".
        ips = sorted(self.tabela.get_children(), key=ipaddress.ip_address)
        for i, ip in enumerate(ips):
            self.tabela.move(ip, "", i)

    @staticmethod
    def _texto_portas(portas):
        return ", ".join(scanner.nome_porta(p) for p in portas) if portas else "nenhuma no intervalo"

    def _atualizar_resumo(self):
        # Conta os status e escreve o resumo à direita da barra de progresso.
        v = list(self.status.values())
        texto = "Online: %d   (só por ARP: %d)   Offline: %d" % (
            v.count("online") + v.count("arp"), v.count("arp"), v.count("offline"))
        if self.conflitos:
            texto += "   Colisões de IP: %d" % len(self.conflitos)
        self.lbl_resumo.configure(text=texto)


# Ponto de partida do programa: cria a janela, monta o NetProbe dentro dela e
# entra no "laço de eventos" do Tkinter (mainloop), que fica esperando cliques
# até a janela ser fechada.
if __name__ == "__main__":
    raiz = tk.Tk()
    NetProbeApp(raiz)
    raiz.mainloop()
