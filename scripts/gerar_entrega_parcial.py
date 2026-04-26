"""
Gera o documento de entrega parcial (PDF, máx. 4 páginas) para o MC859.
"""

import json
import os
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
DATA = ROOT / "data"
OUT = ROOT / "Entrega_Parcial_MC859.pdf"

REPO = "https://github.com/marcinholsp/Projeto_MC859"

with open(DATA / "stats.json", encoding="utf-8") as f:
    stats = json.load(f)

# ---------------------------------------------------------------------------
# Estilos
# ---------------------------------------------------------------------------
BASE = getSampleStyleSheet()

titulo = ParagraphStyle(
    "titulo",
    parent=BASE["Heading1"],
    fontSize=14,
    leading=18,
    alignment=TA_CENTER,
    spaceAfter=4,
)
subtitulo = ParagraphStyle(
    "subtitulo",
    parent=BASE["Normal"],
    fontSize=10,
    leading=13,
    alignment=TA_CENTER,
    spaceAfter=2,
)
secao = ParagraphStyle(
    "secao",
    parent=BASE["Heading2"],
    fontSize=11,
    leading=14,
    spaceBefore=10,
    spaceAfter=4,
    textColor=colors.HexColor("#1a3a5c"),
)
corpo = ParagraphStyle(
    "corpo",
    parent=BASE["Normal"],
    fontSize=9.5,
    leading=14,
    alignment=TA_JUSTIFY,
    spaceAfter=6,
)
negrito = ParagraphStyle(
    "negrito",
    parent=corpo,
    fontName="Helvetica-Bold",
)
link_style = ParagraphStyle(
    "link",
    parent=corpo,
    textColor=colors.HexColor("#0563c1"),
)

# ---------------------------------------------------------------------------
# Conteúdo
# ---------------------------------------------------------------------------
story = []

# Título
story.append(Paragraph(
    "Análise de Resiliência e Propagação de Vulnerabilidades<br/>"
    "em Grafos de Dependências do Ecossistema Python",
    titulo,
))
story.append(Paragraph("Márcio Levi Sales Prado — RA 183680", subtitulo))
story.append(Paragraph("MC859 — UNICAMP, Abril de 2026", subtitulo))
story.append(Spacer(1, 0.3 * cm))

# ---------------------------------------------------------------------------
# 1. Introdução
# ---------------------------------------------------------------------------
story.append(Paragraph("1. Introdução", secao))

story.append(Paragraph(
    "Este projeto modela o ecossistema de pacotes Python (PyPI) como um "
    "<b>grafo direcionado</b>, em que cada vértice representa um pacote de "
    "software e cada aresta A → B indica que o pacote A declara dependência "
    "direta de runtime sobre B. O objetivo central é identificar pacotes de "
    "alto risco — aqueles cuja falha de segurança pode se propagar amplamente "
    "pelo ecossistema — cruzando métricas estruturais do grafo (centralidade, "
    "grau, componentes fortemente conexas) com vulnerabilidades conhecidas "
    "provenientes do OSV (Open Source Vulnerabilities) e do GitHub Advisory "
    "Database.",
    corpo,
))

story.append(Paragraph(
    "<b>Coleta de dados.</b> A lista dos 3.000 pacotes mais baixados nos "
    "últimos 30 dias foi obtida do serviço público "
    "<i>top-pypi-packages</i> (hugovk.github.io). Para cada pacote-semente, "
    "a API JSON do PyPI (<tt>https://pypi.org/pypi/{package}/json</tt>) foi "
    "consultada para extrair suas dependências diretas de runtime. "
    "O processo expandiu o conjunto de nós recursivamente até atingir um "
    "limite de 8.000 vértices, totalizando 3.359 pacotes únicos e 9.659 "
    "arestas de dependência. Todos os dados são públicos e não requerem "
    "anonimização.",
    corpo,
))

story.append(Paragraph(
    f'Repositório público com os grafos e scripts: '
    f'<a href="{REPO}" color="#0563c1"><u>{REPO}</u></a>',
    corpo,
))

# ---------------------------------------------------------------------------
# 2. Tamanho do grafo
# ---------------------------------------------------------------------------
story.append(Paragraph("2. Tamanho do Grafo", secao))

table_data = [
    ["Métrica", "Valor"],
    ["Número de vértices", f"{stats['n_vertices']:,}".replace(",", ".")],
    ["Número de arestas", f"{stats['n_arestas']:,}".replace(",", ".")],
    ["Grau médio (in + out)", f"{stats['grau_medio']:.2f}"],
    ["In-degree médio", f"{stats['in_degree_medio']:.2f}"],
    ["Out-degree médio", f"{stats['out_degree_medio']:.2f}"],
    ["In-degree máximo", f"{stats['in_degree_max']} (typing-extensions)"],
    ["Out-degree máximo", f"{stats['out_degree_max']}"],
]

t = Table(table_data, colWidths=[9 * cm, 8 * cm])
t.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a5c")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f2f6fb"), colors.white]),
    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#aaaaaa")),
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("TOPPADDING", (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ("ALIGN", (1, 0), (1, -1), "CENTER"),
]))
story.append(t)
story.append(Spacer(1, 0.3 * cm))

story.append(Paragraph(
    "O grafo exibe distribuição de graus em <i>lei de potência</i> "
    "(scale-free), com expoentes −1,13 para o in-degree e −1,44 para o grau "
    "total (estimados por regressão log-log). Hubs como "
    "<b>typing-extensions</b> (in-degree 495), <b>requests</b> (253) e "
    "<b>numpy</b> (215) concentram a maior parte das dependências.",
    corpo,
))

# ---------------------------------------------------------------------------
# 3. Distribuição de graus
# ---------------------------------------------------------------------------
story.append(Paragraph("3. Distribuição de Graus", secao))

img_deg = Image(str(ASSETS / "degree_distribution.png"), width=16 * cm, height=7 * cm)
story.append(img_deg)
story.append(Spacer(1, 0.15 * cm))
story.append(Paragraph(
    "<b>Figura 1.</b> Distribuição de graus em escala log-log. À esquerda: "
    "in-degree (número de dependentes); à direita: grau total (in + out). "
    "A linha tracejada indica o ajuste por lei de potência.",
    ParagraphStyle("caption", parent=corpo, fontSize=8.5, alignment=TA_CENTER,
                   textColor=colors.HexColor("#555555")),
))

# ---------------------------------------------------------------------------
# 4. Componentes Fortemente Conexas
# ---------------------------------------------------------------------------
story.append(Paragraph("4. Componentes Fortemente Conexas (CFCs)", secao))

story.append(Paragraph(
    f"O algoritmo de Kosaraju identificou <b>{stats['n_sccs']:,}</b> "
    f"componentes fortemente conexas (CFCs). Desse total, "
    f"<b>{stats['n_singletons_scc']:,} são singletons</b> (99,94 %), "
    f"confirmando que o ecossistema PyPI é essencialmente "
    f"<i>acíclico</i> — dependências circulares são raras e restritas a "
    f"grupos muito pequenos. Apenas 2 CFCs possuem mais de um vértice: "
    f"uma com 2 vértices e outra com <b>{stats['maior_scc']} vértices</b> "
    f"(a maior CFC encontrada).".replace(",", "."),
    corpo,
))

# ---------------------------------------------------------------------------
# 5. Distribuição de tamanhos das CFCs
# ---------------------------------------------------------------------------
story.append(Paragraph("5. Distribuição dos Tamanhos das CFCs", secao))

img_scc = Image(str(ASSETS / "scc_distribution.png"), width=16 * cm, height=6.5 * cm)
story.append(img_scc)
story.append(Spacer(1, 0.15 * cm))
story.append(Paragraph(
    "<b>Figura 2.</b> Distribuição dos tamanhos das CFCs. À esquerda: "
    "visão geral (3.349 singletons dominam o histograma). À direita: zoom "
    "nas CFCs com mais de 1 vértice — apenas duas existem, de tamanhos 2 e "
    "8 vértices, evidenciando a quase-ausência de ciclos de dependência.",
    ParagraphStyle("caption", parent=corpo, fontSize=8.5, alignment=TA_CENTER,
                   textColor=colors.HexColor("#555555")),
))

story.append(Spacer(1, 0.4 * cm))
story.append(Paragraph(
    "A predominância de singletons é esperada em ecossistemas de pacotes "
    "maduros: gerentes de pacotes como <i>pip</i> exigem grafo acíclico para "
    "resolver dependências deterministicamente. As raras dependências "
    "circulares encontradas podem indicar versões de compatibilidade cruzada "
    "ou interdependências opcionais não declaradas corretamente.",
    corpo,
))

# ---------------------------------------------------------------------------
# Gera o PDF
# ---------------------------------------------------------------------------
doc = SimpleDocTemplate(
    str(OUT),
    pagesize=A4,
    leftMargin=2.5 * cm,
    rightMargin=2.5 * cm,
    topMargin=2 * cm,
    bottomMargin=2 * cm,
)
doc.build(story)
print(f"PDF gerado: {OUT}")
