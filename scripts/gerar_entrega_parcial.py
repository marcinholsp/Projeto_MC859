"""
Gera o documento de entrega parcial (PDF, máx. 4 páginas) para o MC859.
"""

import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT   = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
DATA   = ROOT / "data"
OUT    = ROOT / "Entrega_Parcial_MC859.pdf"
REPO   = "https://github.com/marcinholsp/Projeto_MC859"

with open(DATA / "stats.json", encoding="utf-8") as f:
    stats = json.load(f)

with open(DATA / "vuln_stats.json", encoding="utf-8") as f:
    vstats = json.load(f)

# -- Estilos ------------------------------------------------------------------
BASE = getSampleStyleSheet()

titulo = ParagraphStyle("titulo", parent=BASE["Heading1"],
    fontSize=14, leading=18, alignment=TA_CENTER, spaceAfter=3)
subtitulo = ParagraphStyle("subtitulo", parent=BASE["Normal"],
    fontSize=10, leading=13, alignment=TA_CENTER, spaceAfter=2)
secao = ParagraphStyle("secao", parent=BASE["Heading2"],
    fontSize=11, leading=14, spaceBefore=9, spaceAfter=4,
    textColor=colors.HexColor("#1a3a5c"))
corpo = ParagraphStyle("corpo", parent=BASE["Normal"],
    fontSize=9.5, leading=14, alignment=TA_JUSTIFY, spaceAfter=5)
caption = ParagraphStyle("caption", parent=BASE["Normal"],
    fontSize=8.5, leading=12, alignment=TA_CENTER,
    textColor=colors.HexColor("#555555"), spaceAfter=4)
nota = ParagraphStyle("nota", parent=BASE["Normal"],
    fontSize=8.5, leading=12, alignment=TA_JUSTIFY,
    textColor=colors.HexColor("#444444"), spaceAfter=4,
    leftIndent=10, rightIndent=10)

AZUL   = colors.HexColor("#1a3a5c")
AZUL_L = colors.HexColor("#f2f6fb")

def hr():
    return HRFlowable(width="100%", thickness=0.5,
                      color=colors.HexColor("#cccccc"), spaceAfter=4, spaceBefore=2)

def tabela(data, col_widths):
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  AZUL),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),  [AZUL_L, colors.white]),
        ("GRID",         (0, 0), (-1, -1), 0.35, colors.HexColor("#bbbbbb")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("ALIGN",        (1, 0), (-1, -1), "CENTER"),
    ]))
    return t

# -- Conteúdo -----------------------------------------------------------------
story = []

# -- Cabeçalho ----------------------------------------------------------------
story.append(Paragraph(
    "Análise de Resiliência e Propagação de Vulnerabilidades<br/>"
    "em Grafos de Dependências do Ecossistema Python", titulo))
story.append(Paragraph("Márcio Levi Sales Prado — RA 183680", subtitulo))
story.append(Paragraph("MC859 — UNICAMP, Abril de 2026", subtitulo))
story.append(hr())
story.append(Spacer(1, 0.1*cm))

# -- 1. Introdução -------------------------------------------------------------
story.append(Paragraph("1. Introdução", secao))
story.append(Paragraph(
    "O ecossistema de pacotes Python (PyPI) é um dos maiores repositórios de "
    "software livre do mundo, com mais de 500 mil pacotes publicados. A cadeia "
    "de dependências entre esses pacotes forma uma rede complexa: quando um "
    "pacote amplamente usado contém uma vulnerabilidade de segurança, todos os "
    "projetos que dependem dele — direta ou indiretamente — ficam expostos ao "
    "mesmo risco.", corpo))
story.append(Paragraph(
    "Este projeto modela esse ecossistema como um <b>grafo direcionado</b>, no "
    "qual cada vértice representa um pacote e cada aresta <b>A → B</b> indica "
    "que A declara dependência direta de runtime sobre B. O objetivo central é "
    "identificar pacotes de alto risco combinando métricas estruturais do grafo "
    "(centralidade, grau, componentes fortemente conexas) com dados reais de "
    "uso (downloads mensais) e vulnerabilidades conhecidas do OSV "
    "(<i>Open Source Vulnerabilities</i>) e do GitHub Advisory Database.", corpo))

story.append(Paragraph("<b>Coleta de dados.</b> "
    "Foram combinadas duas fontes: (i) os <b>8.000 pacotes mais baixados</b> "
    "nos últimos 30 dias (<i>top-pypi-packages</i>, hugovk.github.io) e (ii) "
    "<b>40.000 pacotes adicionais</b> do <i>PyPI Simple Index</i>. "
    "Para cada semente, a API JSON do PyPI extraiu dependências de runtime de "
    "<tt>requires_dist</tt>, ignorando extras opcionais. "
    "Com 20 threads paralelas e BFS transitivo, o grafo resultante tem "
    f"<b>{stats['n_vertices']:,} pacotes</b> e <b>{stats['n_arestas']:,} arestas</b>. ".replace(",",".") +
    "Cada nó foi anotado com downloads mensais para ponderar a propagação de vulnerabilidades.", corpo))

story.append(Paragraph(
    f'Repositório com instâncias e scripts: '
    f'<a href="{REPO}" color="#0563c1"><u>{REPO}</u></a>', corpo))

# -- 2. Tamanho do Grafo -------------------------------------------------------
story.append(Paragraph("2. Tamanho do Grafo", secao))

metricas = [
    ["Métrica", "Valor"],
    ["Número de vértices (pacotes)", f"{stats['n_vertices']:,}".replace(",",".")],
    ["Número de arestas (dependências)", f"{stats['n_arestas']:,}".replace(",",".")],
    ["Grau médio (in + out)", f"{stats['grau_medio']:.2f}"],
    ["In-degree médio (dependentes diretos)", f"{stats['in_degree_medio']:.2f}"],
    ["Out-degree médio (dependências diretas)", f"{stats['out_degree_medio']:.2f}"],
    ["In-degree máximo", f"{stats['in_degree_max']:,} (numpy)".replace(",",".")],
    ["Out-degree máximo", f"{stats['out_degree_max']}"],
    ["CFCs totais", f"{stats['n_sccs']:,}".replace(",",".")],
    ["Maior CFC", f"{stats['maior_scc']} vértices"],
    ["CFCs singleton (1 vértice)", f"{stats['n_singletons_scc']:,}".replace(",",".")],
    ["Componentes fracamente conexas (CFrCs)", f"{stats['n_wccs']:,}".replace(",",".")],
    ["Maior componente fracamente conexa", f"{stats['maior_wcc']:,} vértices".replace(",",".")],
]
story.append(tabela(metricas, [10*cm, 7*cm]))
story.append(Spacer(1, 0.25*cm))

story.append(Paragraph(
    f"A densidade do grafo é baixa ({stats['n_arestas']:,} arestas para "
    f"{stats['n_vertices']:,} nós), o que é esperado em redes de dependências "
    f"reais: cada pacote declara, em média, cerca de "
    f"{stats['out_degree_medio']:.1f} dependências diretas. O in-degree "
    f"máximo de {stats['in_degree_max']:,} (<tt>numpy</tt>) evidencia a "
    f"presença de <i>hubs</i> — pacotes que servem de base para milhares "
    f"de outros — característica típica de redes livres de escala "
    f"(<i>scale-free</i>).".replace(",","."), corpo))

# -- 3. Distribuição de Graus --------------------------------------------------
story.append(Paragraph("3. Distribuição de Graus", secao))

img_deg = Image(str(ASSETS/"degree_distribution.png"), width=15.5*cm, height=6.5*cm)
story.append(img_deg)
story.append(Paragraph(
    "<b>Figura 1.</b> Distribuição de graus em escala log-log. À esquerda: "
    "in-degree (número de dependentes diretos); à direita: grau total (in + out). "
    "A linha tracejada mostra o ajuste por lei de potência.", caption))

story.append(Paragraph(
    "A distribuição de graus segue uma <b>lei de potência</b> "
    "(<i>power-law</i>) em escala log-log, com expoentes estimados por "
    "regressão linear de −0,91 para o in-degree e −1,20 para o grau total. "
    "Esse padrão — característico de redes livres de escala — implica que "
    "a maioria dos pacotes tem poucos dependentes, enquanto um número muito "
    "reduzido de hubs concentra milhares deles. Do ponto de vista de "
    "segurança, esses hubs são candidatos naturais a pontos críticos: uma "
    "vulnerabilidade em <tt>numpy</tt> (in-degree 6.479), <tt>requests</tt> "
    "(6.463) ou <tt>pydantic</tt> (4.461) pode afetar, direta ou "
    "indiretamente, grande parte do ecossistema.", corpo))

story.append(Paragraph(
    "A Figura 2 apresenta os 20 pacotes com maior in-degree. <tt>numpy</tt> e "
    "<tt>requests</tt> destacam-se em uma faixa muito acima dos demais, "
    "seguidos por <tt>pydantic</tt>, <tt>pandas</tt> e <tt>pyyaml</tt>. "
    "Curiosamente, <tt>typing-extensions</tt>, líder em estudos restritos "
    "ao top-3.000 pacotes, aparece apenas em sexta posição quando o escopo "
    "é ampliado: muitos dos pacotes mais populares já dependem dele, mas "
    "ele tem alcance estrutural menor que bibliotecas científicas como "
    "<tt>numpy</tt>, que penetra em ferramentas de ML, dados e análise — "
    "ilustrando como o tamanho da amostra afeta o ranking de centralidade.",
    corpo))

img_top = Image(str(ASSETS/"top_packages.png"), width=15.5*cm, height=6.8*cm)
story.append(img_top)
story.append(Paragraph(
    "<b>Figura 2.</b> Top 20 pacotes por in-degree (número de pacotes que "
    "dependem diretamente de cada um).", caption))

# -- 4. Componentes Fortemente Conexas -----------------------------------------
story.append(Paragraph("4. Componentes Fortemente Conexas (CFCs)", secao))

pct_singleton = 100 * stats["n_singletons_scc"] / stats["n_sccs"]
n_cfc_multi   = stats["n_sccs"] - stats["n_singletons_scc"]
story.append(Paragraph(
    f"O algoritmo de Tarjan identificou <b>{stats['n_sccs']:,} CFCs</b>. "
    f"Desse total, <b>{stats['n_singletons_scc']:,} são singletons</b> "
    f"({pct_singleton:.2f}%), confirmando que o grafo de dependências PyPI é "
    f"essencialmente <i>acíclico</i>. Gerenciadores de pacotes como "
    f"<tt>pip</tt> exigem um grafo acíclico para resolver dependências "
    f"deterministicamente, de modo que dependências circulares são "
    f"proibidas em teoria — as raras exceções encontradas "
    f"({n_cfc_multi} CFCs com mais de um vértice, de tamanhos entre 2 e "
    f"<b>{stats['maior_scc']}</b>) podem indicar versões de compatibilidade "
    f"cruzada ou dependências opcionais não declaradas corretamente.".replace(",","."), corpo))

story.append(Paragraph(
    "A Figura 3 ilustra a distribuição de tamanhos das CFCs. O painel "
    "esquerdo evidencia o domínio absoluto dos singletons; o painel direito "
    "amplia as CFCs com mais de um vértice, confirmando que dependências "
    "circulares são eventos raros e de pequena escala neste ecossistema.",
    corpo))

img_scc = Image(str(ASSETS/"scc_distribution.png"), width=15.5*cm, height=6.0*cm)
story.append(img_scc)
story.append(Paragraph(
    f"<b>Figura 3.</b> Distribuição dos tamanhos das CFCs. Esquerda: visão "
    f"geral ({stats['n_singletons_scc']:,} singletons dominam). Direita: zoom "
    f"nas {n_cfc_multi} CFCs com mais de 1 vértice (tamanhos entre 2 e "
    f"{stats['maior_scc']}).".replace(",","."), caption))

# -- 5. Componentes Fracamente Conexas -----------------------------------------
story.append(Paragraph("5. Componentes Fracamente Conexas (CFrCs)", secao))

pct_gigante = 100 * stats["maior_wcc"] / stats["n_vertices"]
story.append(Paragraph(
    f"Ignorando a direção das arestas, o grafo possui "
    f"<b>{stats['n_wccs']:,} componentes fracamente conexas</b>. "
    f"A maior delas contém <b>{stats['maior_wcc']:,} vértices</b> "
    f"({pct_gigante:.1f}% do total) — o chamado <i>componente gigante</i>, "
    f"presente em praticamente todas as redes reais de larga escala. "
    f"As demais {stats['n_wccs']-1:,} componentes são, em sua maioria, "
    f"pacotes isolados ou pequenos subgrafos sem ligação com o núcleo "
    f"principal do ecossistema — pacotes de nicho, abandonados, ou cujos "
    f"metadados <tt>requires_dist</tt> não declaram dependências "
    f"runtime.".replace(",","."), corpo))

story.append(Paragraph(
    f"A existência de um componente gigante cobrindo {pct_gigante:.1f}% do "
    f"grafo tem implicações diretas para a análise de propagação de "
    f"vulnerabilidades: uma falha em qualquer pacote dentro desse componente "
    f"pode, em princípio, atingir até "
    f"{stats['maior_wcc']-1:,} outros pacotes por caminhos de "
    f"dependência. Essa conectividade motivou o uso do modelo Independent "
    f"Cascade para quantificar o alcance real de cada "
    f"vulnerabilidade.".replace(",","."), corpo))

# -- 6. Análise de Vulnerabilidades -------------------------------------------
story.append(PageBreak())
story.append(Paragraph("6. Análise de Vulnerabilidades", secao))

n_vuln  = vstats["vulnerable_nodes"]
pct_vuln = vstats["pct_vulnerable"]
story.append(Paragraph(
    f"A base OSV (<i>Open Source Vulnerabilities</i>) e o GitHub Advisory Database "
    f"foram consultados para cada nó do grafo. Foram identificados "
    f"<b>{n_vuln} pacotes com ao menos um CVE</b> ({pct_vuln:.1f}% dos "
    f"{stats['n_vertices']:,} pacotes totais). Para cada pacote vulnerável, o "
    f"CVSS máximo foi extraído via biblioteca <tt>cvss</tt> e armazenado como "
    f"atributo do nó no grafo anotado "
    f"(<tt>pypi_dependency_graph_vuln.graphml</tt>).".replace(",","."), corpo))

story.append(Paragraph("<b>Modelo Independent Cascade (IC) ponderado por downloads.</b> "
    "Em vez de BFS/DFS determinístico, o projeto usa o modelo IC para responder: "
    "<i>se o pacote B for comprometido, com que probabilidade o pacote A que depende "
    "de B será afetado?</i> A probabilidade de propagação da aresta B → A (no grafo "
    "reverso) é proporcional à fração de downloads de B em relação a todas as "
    "dependências de A:", corpo))

formula_style = ParagraphStyle("formula", parent=BASE["Normal"],
    fontSize=9, leading=13, alignment=TA_CENTER,
    fontName="Courier", spaceAfter=5,
    textColor=colors.HexColor("#1a3a5c"))
story.append(Paragraph(
    "p(B→A) = log1p(downloads_B) / Σ log1p(downloads_dep),  dep ∈ deps(A)",
    formula_style))

story.append(Paragraph(
    "O score de criticidade combina gravidade real e alcance prático:", corpo))
story.append(Paragraph(
    "risk(v) = CVSS(v) × log1p(downloads_IC_afetados) × log1p(downloads_próprios)",
    formula_style))

story.append(Paragraph(
    "500 simulações Monte Carlo foram executadas por pacote vulnerável. "
    "Esse score diferencia centralidade estrutural de impacto prático: um pacote "
    "com muitos dependentes mas pouco uso real obtém score baixo.", corpo))

# Tabela top 5
top5 = vstats["top_risks"][:5]
def fmt_dl(n):
    if n >= 1e9:
        return f"{n/1e9:.2f} B"
    if n >= 1e6:
        return f"{n/1e6:.0f} M"
    return f"{n:,}".replace(",",".")

risk_data = [["Pacote", "CVSS", "CVEs", "Downloads próprios", "Downloads IC afetados", "Risk score"]]
for r in top5:
    risk_data.append([
        r["package"],
        f"{r['cvss']:.1f}",
        str(r["vuln_count"]),
        fmt_dl(r["own_downloads"]),
        fmt_dl(r["ic_active_dl"]),
        f"{r['risk_score']:.0f}",
    ])
story.append(tabela(risk_data, [3.5*cm, 1.3*cm, 1.0*cm, 3.2*cm, 3.5*cm, 2.5*cm]))
story.append(Spacer(1, 0.2*cm))

img_risk = Image(str(ASSETS/"vuln_risk_scores.png"), width=15.5*cm, height=6.2*cm)
story.append(img_risk)
story.append(Paragraph(
    "<b>Figura 4.</b> Top 20 pacotes por risco IC ponderado por downloads. "
    "A barra combina CVSS, alcance IC e volume de uso.", caption))

story.append(Paragraph(
    "A Figura 5 (repositório) compara o alcance BFS estrutural com o alcance IC real: "
    "pacotes com muitos dependentes transitivos mas baixo IC são dependências opcionais "
    "ou pouco utilizadas na prática, evidenciando a importância de ponderar pelo uso real.",
    corpo))

# -- Rodapé -------------------------------------------------------------------
story.append(Spacer(1, 0.2*cm))
story.append(hr())
story.append(Paragraph(
    f"Instâncias disponíveis em: "
    f'<a href="{REPO}" color="#0563c1"><u>{REPO}</u></a> — '
    f"formatos GraphML e GEXF, pasta <tt>data/</tt>.",
    ParagraphStyle("rodape", parent=BASE["Normal"], fontSize=8,
                   alignment=TA_CENTER, textColor=colors.HexColor("#666666"))))

# -- Gera PDF -----------------------------------------------------------------
doc = SimpleDocTemplate(
    str(OUT), pagesize=A4,
    leftMargin=2.5*cm, rightMargin=2.5*cm,
    topMargin=2.0*cm,  bottomMargin=2.0*cm,
)
doc.build(story)
print(f"PDF gerado: {OUT}")
