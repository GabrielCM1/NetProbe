"""
Gera o arquivo fabricantes.txt (prefixo do MAC -> fabricante), usado pelo NetProbe
para mostrar quem fabricou cada aparelho.

Os 3 primeiros bytes de um MAC (o "OUI") sao comprados pelo fabricante e registrados
publicamente pelo IEEE. Ex.: F4-E8-4F-... = ZTE, A8-E6-21-... = Amazon.
A fonte e a copia do registro do IEEE mantida pelo projeto Wireshark:
  https://www.wireshark.org/download/automated/data/manuf.gz

So precisa rodar de vez em quando (o registro muda pouco). O NetProbe em si
NUNCA acessa a internet: ele so le o fabricantes.txt que ja vem no projeto.

Uso:
  python atualizar_fabricantes.py             # baixa a lista e gera o arquivo
  python atualizar_fabricantes.py manuf       # usa um arquivo 'manuf' ja baixado
"""
import gzip
import re
import sys
import time
import urllib.request
from pathlib import Path

URL = "https://www.wireshark.org/download/automated/data/manuf.gz"
DESTINO = Path(__file__).resolve().parent / "fabricantes.txt"

# Sufixos de empresa que so ocupam espaco na tabela ("Samsung Electronics Co.,Ltd" -> "Samsung Electronics")
_SUFIXOS = re.compile(
    r"[\s,.]*\b(co\.?,?\s*ltd|co|ltd|limited|inc|incorporated|corp|corporation|llc|gmbh|"
    r"s\.?a|s\.?a\.?s|s\.?r\.?l|ag|b\.?v|oy|ab|a/s|pty|plc|kg|sa de cv|technologies|technology)\.?\s*$",
    re.I)


def limpar_nome(nome: str) -> str:
    nome = " ".join(nome.split())
    anterior = None
    while nome != anterior:                     # tira varios sufixos: "X Technology Co., Ltd."
        anterior = nome
        nome = _SUFIXOS.sub("", nome).strip(" ,.")
    if nome.islower():                          # "zte" -> "ZTE";  "huawei device" -> "Huawei Device"
        nome = nome.upper() if len(nome) <= 4 else nome.title()
    return nome or anterior


def converter(texto: str) -> list:
    """Linhas do 'manuf' -> ['F4E84F\\tZTE', '0055DA1\\tKoolPOS', ...]"""
    linhas = []
    for linha in texto.splitlines():
        if not linha.strip() or linha.startswith("#"):
            continue
        partes = linha.split("\t")
        if len(partes) < 2:
            continue
        bloco = partes[0].strip()
        nome = (partes[2] if len(partes) > 2 and partes[2].strip() else partes[1]).strip()
        bits = int(bloco.split("/")[1]) if "/" in bloco else 24
        hexa = bloco.split("/")[0].replace(":", "").replace("-", "").upper()
        prefixo = hexa[: bits // 4]
        if len(prefixo) in (6, 7, 9) and re.fullmatch(r"[0-9A-F]+", prefixo):
            linhas.append("%s\t%s" % (prefixo, limpar_nome(nome)))
    return linhas


def main():
    if len(sys.argv) > 1:
        texto = Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore")
    else:
        print("Baixando", URL)
        with urllib.request.urlopen(URL, timeout=60) as r:
            texto = gzip.decompress(r.read()).decode("utf-8", errors="ignore")
    linhas = converter(texto)
    cabecalho = [
        "# Fabricantes por prefixo de MAC (OUI) - gerado por atualizar_fabricantes.py em %s"
        % time.strftime("%Y-%m-%d"),
        "# Fonte: registro publico do IEEE, na copia do Wireshark (%s)" % URL,
        "# Formato: PREFIXO<TAB>FABRICANTE  (prefixo de 6, 7 ou 9 digitos hexadecimais)",
    ]
    DESTINO.write_text("\n".join(cabecalho + linhas) + "\n", encoding="utf-8")
    print("Gerado %s com %d fabricantes." % (DESTINO.name, len(linhas)))


if __name__ == "__main__":
    main()
