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

# ── Estilos ──────────────────────────────────────────────────────────────────
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

# ── Conteúdo ─────────────────────────────────────────────────────────────────
story = []

# ── Cabeçalho ────────────────────────────────────────────────────────────────
story.append(Paragraph(
    "Análise de Resiliência e Propagação de Vulnerabilidades<br/>"
    "em Grafos de Dependências do Ecossistema Python", titulo))
story.append(Paragraph("Márcio Levi Sales Prado — RA 183680", subtitulo))
story.append(Paragraph("MC859 — UNICAMP, Abril de 2026", subtitulo))
story.append(hr())
story.append(Spacer(1, 0.1*cm))

# ── 1. Introdução ─────────────────────────────────────────────────────────────
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
    "A lista dos 3.000 pacotes mais baixados nos últimos 30 dias foi obtida do "
    "serviço público <i>top-pypi-packages</i> (hugovk.github.io), que agrega "
    "estatísticas oficiais do PyPI. Para cada pacote-semente, a API JSON do "
    "PyPI (<tt>pypi.org/pypi/{pkg}/json</tt>) foi consultada para extrair as "
    "dependências diretas de runtime declaradas no campo <tt>requires_dist</tt>, "
    "filtrando dependências opcionais (marcadas com <tt>extra ==</tt>). "
    "O processo expandiu o conjunto recursivamente via BFS até o limite de "
    "8.000 vértices, resultando em <b>3.359 pacotes</b> e <b>9.659 arestas</b>. "
    "Todos os dados provêm de APIs públicas e não requerem anonimização. "
    "Além das dependências, cada nó foi anotado com o volume de downloads "
    "mensais proveniente da mesma fonte, utilizado para ponderar a análise "
    "de propagação de vulnerabilidades.", corpo))

story.append(Paragraph(
    f'Repositório com instâncias e scripts: '
    f'<a href="{REPO}" color="#0563c1"><u>{REPO}</u></a>', corpo))

# ── 2. Tamanho do Grafo ───────────────────────────────────────────────────────
story.append(Paragraph("2. Tamanho do Grafo", secao))

metricas = [
    ["Métrica", "Valor"],
    ["Número de vértices (pacotes)", f"{stats['n_vertices']:,}".replace(",",".")],
    ["Número de arestas (dependências)", f"{stats['n_arestas']:,}".replace(",",".")],
    ["Grau médio (in + out)", f"{stats['grau_medio']:.2f}"],
    ["In-degree médio (dependentes diretos)", f"{stats['in_degree_medio']:.2f}"],
    ["Out-degree médio (dependências diretas)", f"{stats['out_degree_medio']:.2f}"],
    ["In-degree máximo", f"{stats['in_degree_max']} (typing-extensions)"],
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
    "A densidade do grafo é baixa (9.659 arestas para 3.359 nós), o que é "
    "esperado em redes de dependências reais: cada pacote declara, em média, "
    "menos de 3 dependências diretas. O in-degree máximo de 495 "
    "(<tt>typing-extensions</tt>) evidencia a presença de <i>hubs</i> — "
    "pacotes que servem de base para centenas de outros — característica "
    "típica de redes livres de escala (<i>scale-free</i>).", corpo))

# ── 3. Distribuição de Graus ──────────────────────────────────────────────────
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
    "regressão linear de −1,13 para o in-degree e −1,44 para o grau total. "
    "Esse padrão — característico de redes livres de escala — implica que "
    "a maioria dos pacotes tem poucos dependentes, enquanto um número muito "
    "reduzido de hubs concentra centenas deles. Do ponto de vista de "
    "segurança, esses hubs são candidatos naturais a pontos críticos: uma "
    "vulnerabilidade em <tt>typing-extensions</tt> (in-degree 495) ou "
    "<tt>requests</tt> (253) pode afetar, direta ou indiretamente, grande "
    "parte do ecossistema.", corpo))

story.append(Paragraph(
    "A Figura 2 apresenta os 20 pacotes com maior in-degree. Observa-se que "
    "<tt>typing-extensions</tt> destaca-se com folga — seu in-degree é quase "
    "o dobro do segundo colocado (<tt>requests</tt>). Também chamam atenção "
    "os pacotes <tt>pyobjc-core</tt> e <tt>pyobjc-framework-cocoa</tt>, "
    "específicos para macOS, que aparecem no top-10 estrutural mas têm "
    "downloads muito menores que <tt>numpy</tt> ou <tt>requests</tt> — "
    "ilustrando por que centralidade estrutural isolada não é suficiente "
    "para avaliar criticidade.", corpo))

img_top = Image(str(ASSETS/"top_packages.png"), width=15.5*cm, height=6.8*cm)
story.append(img_top)
story.append(Paragraph(
    "<b>Figura 2.</b> Top 20 pacotes por in-degree (número de pacotes que "
    "dependem diretamente de cada um).", caption))

# ── 4. Componentes Fortemente Conexas ─────────────────────────────────────────
story.append(Paragraph("4. Componentes Fortemente Conexas (CFCs)", secao))

story.append(Paragraph(
    f"O algoritmo de Kosaraju identificou <b>{stats['n_sccs']:,} CFCs</b>. "
    f"Desse total, <b>{stats['n_singletons_scc']:,} são singletons</b> "
    f"(99,94%), confirmando que o grafo de dependências PyPI é "
    f"essencialmente <i>acíclico</i>. Gerenciadores de pacotes como "
    f"<tt>pip</tt> exigem um grafo acíclico para resolver dependências "
    f"deterministicamente, de modo que dependências circulares são "
    f"proibidas em teoria — as raras exceções encontradas "
    f"(2 CFCs com mais de um vértice, de tamanhos 2 e "
    f"<b>{stats['maior_scc']}</b>) podem indicar versões de compatibilidade "
    f"cruzada ou opcionais não declaradas corretamente.".replace(",","."), corpo))

story.append(Paragraph(
    "A Figura 3 ilustra a distribuição de tamanhos das CFCs. O painel "
    "esquerdo evidencia o domínio absoluto dos singletons; o painel direito "
    "amplia as únicas duas CFCs com mais de um vértice, confirmando que "
    "dependências circulares são eventos raros e de pequena escala neste "
    "ecossistema.", corpo))

img_scc = Image(str(ASSETS/"scc_distribution.png"), width=15.5*cm, height=6.0*cm)
story.append(img_scc)
story.append(Paragraph(
    "<b>Figura 3.</b> Distribuição dos tamanhos das CFCs. Esquerda: visão "
    "geral (3.349 singletons dominam). Direita: zoom nas 2 CFCs com mais "
    "de 1 vértice (tamanhos 2 e 8).", caption))

# ── 5. Componentes Fracamente Conexas ─────────────────────────────────────────
story.append(Paragraph("5. Componentes Fracamente Conexas (CFrCs)", secao))

pct_gigante = 100 * stats["maior_wcc"] / stats["n_vertices"]
story.append(Paragraph(
    f"Ignorando a direção das arestas, o grafo possui "
    f"<b>{stats['n_wccs']} componentes fracamente conexas</b>. "
    f"A maior delas contém <b>{stats['maior_wcc']:,} vértices</b> "
    f"({pct_gigante:.1f}% do total) — o chamado <i>componente gigante</i>, "
    f"presente em praticamente todas as redes reais de larga escala. "
    f"As demais {stats['n_wccs']-1} componentes são, em sua maioria, "
    f"pacotes isolados ou pequenos subgrafos sem ligação com o núcleo "
    f"principal do ecossistema, provavelmente pacotes de nicho ou com "
    f"dependências não cobertas pelo escopo da coleta.".replace(",","."), corpo))

story.append(Paragraph(
    "A existência de um componente gigante cobrindo quase 88% do grafo "
    "tem implicações diretas para a análise de propagação de "
    "vulnerabilidades: uma falha em qualquer pacote dentro desse componente "
    "pode, em princípio, atingir outros 2.947 pacotes por caminhos de "
    "dependência. Essa observação motiva o uso de modelos de propagação "
    "probabilística — como o Independent Cascade — em etapas futuras do "
    "projeto, para quantificar o alcance real considerando a intensidade "
    "de uso de cada dependência.", corpo))

# ── Rodapé ───────────────────────────────────────────────────────────────────
story.append(Spacer(1, 0.2*cm))
story.append(hr())
story.append(Paragraph(
    f"Instâncias disponíveis em: "
    f'<a href="{REPO}" color="#0563c1"><u>{REPO}</u></a> — '
    f"formatos GraphML e GEXF, pasta <tt>data/</tt>.",
    ParagraphStyle("rodape", parent=BASE["Normal"], fontSize=8,
                   alignment=TA_CENTER, textColor=colors.HexColor("#666666"))))

# ── Gera PDF ─────────────────────────────────────────────────────────────────
doc = SimpleDocTemplate(
    str(OUT), pagesize=A4,
    leftMargin=2.5*cm, rightMargin=2.5*cm,
    topMargin=2.0*cm,  bottomMargin=2.0*cm,
)
doc.build(story)
print(f"PDF gerado: {OUT}")
