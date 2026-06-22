"""
detect_communities.py
======================
Detecção e visualização de comunidades no grafo de dependências PyPI,
cruzando a estrutura comunitária com as vulnerabilidades conhecidas.

Motivação:
    Vulnerabilidades raramente estão distribuídas uniformemente pelo
    ecossistema. Pacotes que compartilham dependências tendem a formar
    "bairros" densamente conectados (comunidades). Se uma dessas
    comunidades concentra muitos pacotes vulneráveis E é muito usada,
    ela representa um vetor de risco sistêmico: uma única falha pode
    se propagar por todo o bairro. Este script identifica esses bairros
    de risco usando maximização de modularidade (Louvain).

Por que grafo NÃO direcionado?
    Modularidade e o algoritmo de Louvain são definidos sobre grafos
    não direcionados. A direção da aresta (A depende de B) é irrelevante
    para a pergunta "quais pacotes formam um agrupamento coeso?" — o que
    importa é a co-ocorrência de conexões. Por isso convertemos o DiGraph
    para Graph (não direcionado) e trabalhamos no maior componente
    fracamente conexo, onde a noção de comunidade é significativa.

-------------------------------------------------------------------------
PSEUDOCÓDIGO — ALGORITMO DE LOUVAIN (maximização de modularidade)
-------------------------------------------------------------------------
    Modularidade Q mede o quão melhor que o acaso é uma partição:
        Q = (1/2m) * Σ_ij [ A_ij - (k_i * k_j)/(2m) ] * δ(c_i, c_j)
    onde A_ij = peso da aresta i-j, k_i = grau (ponderado) de i,
          m = soma de todos os pesos, c_i = comunidade de i,
          δ = 1 se c_i == c_j, senão 0.

    LOUVAIN(G):
        atribua cada nó à sua própria comunidade
        repita:
            # --- Fase 1: otimização local (movimentação gananciosa) ---
            melhorou = falso
            para cada nó i (em ordem):
                remova i de sua comunidade
                para cada comunidade C vizinha de i:
                    calcule ΔQ de mover i para C
                escolha a comunidade C* com maior ΔQ
                se ΔQ(C*) > 0:
                    mova i para C*
                    melhorou = verdadeiro
            # --- Fase 2: agregação (coarsening) ---
            construa novo grafo onde cada comunidade vira um super-nó;
            pesos de arestas = soma dos pesos entre/dentro das comunidades
            G <- novo grafo agregado
        até que Q não aumente mais (nenhuma fase 1 melhora)
        retorne a partição (desdobrada de volta aos nós originais)

    Complexidade empírica ~ O(n log n); resolução controla o tamanho
    típico das comunidades (resolution=1.0 é o padrão clássico).
-------------------------------------------------------------------------

Definição de "risco da comunidade" (usada aqui):
    risk = frac_vuln * cvss_medio_vuln * log1p(downloads_totais)
      - frac_vuln          : fração de pacotes vulneráveis na comunidade
      - cvss_medio_vuln    : gravidade média entre os pacotes vulneráveis
      - log1p(downloads)   : relevância/exposição real da comunidade
    Combina prevalência da falha × gravidade × exposição.

Saída:
    data/pypi_dependency_graph_communities.graphml  (grafo anotado)
    data/community_stats.json
    assets/communities_size_distribution.png
    assets/communities_risk.png
    assets/communities_network.png

Uso:
    pip install networkx matplotlib numpy python-louvain
    python scripts/detect_communities.py
"""

import json
import logging
import random
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import networkx as nx

# python-louvain expõe o pacote como `community`
import community as community_louvain

# ---------------------------------------------
#  CONFIGURAÇÕES
# ---------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR     = PROJECT_ROOT / "data"
FIGURES_DIR  = PROJECT_ROOT / "assets"

INPUT_GRAPHML  = DATA_DIR / "pypi_dependency_graph_vuln.graphml"
OUTPUT_GRAPHML = DATA_DIR / "pypi_dependency_graph_communities.graphml"
OUTPUT_JSON    = DATA_DIR / "community_stats.json"
FIG_DPI        = 150

SEED       = 42      # reprodutibilidade (Louvain e layouts)
TOP_N_RISK = 10      # nº de comunidades de risco a reportar
TOP_MEMBERS = 8      # nº de pacotes-chave listados por comunidade

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------
#  ESTILO GLOBAL DOS GRÁFICOS (GitHub dark)
# ---------------------------------------------
plt.rcParams.update({
    "figure.facecolor": "#0d1117",
    "axes.facecolor":   "#161b22",
    "axes.edgecolor":   "#30363d",
    "axes.labelcolor":  "#c9d1d9",
    "axes.titlecolor":  "#f0f6fc",
    "axes.titlesize":   13,
    "axes.labelsize":   11,
    "xtick.color":      "#8b949e",
    "ytick.color":      "#8b949e",
    "grid.color":       "#21262d",
    "grid.linestyle":   "--",
    "grid.linewidth":   0.6,
    "text.color":       "#c9d1d9",
    "legend.facecolor": "#161b22",
    "legend.edgecolor": "#30363d",
    "font.family":      "monospace",
})
ACCENT  = "#58a6ff"   # azul
ACCENT2 = "#3fb950"   # verde
ACCENT3 = "#f78166"   # laranja/vermelho
ACCENT4 = "#d2a8ff"   # roxo


# =============================================
#  CARGA E UTILITÁRIOS
# =============================================

def load_graph(path: Path) -> nx.DiGraph:
    log.info(f"Carregando grafo: {path} ({path.stat().st_size / 1e6:.1f} MB)")
    G = nx.read_graphml(path)
    log.info(f"  {G.number_of_nodes():,} nós | {G.number_of_edges():,} arestas "
             f"| direcionado={G.is_directed()}")
    return G


def get_float(G, node, attr, default=0.0):
    """Lê um atributo numérico de nó com tolerância a valores ausentes/vazios."""
    v = G.nodes[node].get(attr, default)
    try:
        return float(v) if v not in (None, "") else default
    except (ValueError, TypeError):
        return default


def to_undirected_largest_wcc(G: nx.DiGraph) -> nx.Graph:
    """
    Converte o DiGraph para grafo NÃO direcionado e restringe ao maior
    componente fracamente conexo (WCC).

    Justificativa: Louvain/modularidade operam sobre grafos não
    direcionados; e fora do maior componente as "comunidades" são
    fragmentos triviais que poluem a distribuição.
    """
    # Maior componente fracamente conexo (no grafo direcionado original)
    wccs = sorted(nx.weakly_connected_components(G), key=len, reverse=True)
    largest = wccs[0]
    log.info(f"Maior WCC: {len(largest):,} nós "
             f"({100 * len(largest) / G.number_of_nodes():.1f}% do grafo) "
             f"| total de WCCs: {len(wccs):,}")

    sub = G.subgraph(largest)
    # Conversão para não-direcionado: arestas A->B e B->A colapsam em A-B
    H = sub.to_undirected()
    # Preserva referência ao grafo direcionado para métricas de in-degree
    log.info(f"Subgrafo não-direcionado: {H.number_of_nodes():,} nós | "
             f"{H.number_of_edges():,} arestas")
    return H


# =============================================
#  DETECÇÃO DE COMUNIDADES (LOUVAIN)
# =============================================

def detect_communities(H: nx.Graph) -> tuple[dict, float]:
    """
    Roda Louvain (maximização de modularidade) sobre o grafo não-direcionado.

    Retorna:
        partition  : dict {nó -> id_comunidade}
        modularity : modularidade global Q da partição
    """
    log.info("Executando Louvain (maximização de modularidade)...")
    # random_state fixo garante reprodutibilidade da heurística gananciosa
    partition = community_louvain.best_partition(H, random_state=SEED)
    modularity = community_louvain.modularity(partition, H)

    n_comm = len(set(partition.values()))
    log.info(f"  Comunidades detectadas : {n_comm:,}")
    log.info(f"  Modularidade global Q  : {modularity:.4f}")
    return partition, modularity


def community_size_distribution(partition: dict) -> Counter:
    """Conta quantos nós há em cada comunidade -> Counter {id: tamanho}."""
    sizes = Counter(partition.values())
    size_hist = Counter(sizes.values())  # {tamanho: nº de comunidades desse tamanho}
    log.info("  Distribuição de tamanhos (resumo):")
    log.info(f"    maior comunidade : {max(sizes.values()):,} nós")
    log.info(f"    menor comunidade : {min(sizes.values()):,} nós")
    log.info(f"    tamanho mediano  : {int(np.median(list(sizes.values())))} nós")
    return sizes, size_hist


# =============================================
#  ANÁLISE DE RISCO POR COMUNIDADE
# =============================================

def analyze_community_risk(G_dir: nx.DiGraph, H: nx.Graph,
                           partition: dict) -> list[dict]:
    """
    Para cada comunidade, agrega métricas de vulnerabilidade e exposição,
    e calcula o "risco da comunidade".

        risk = frac_vuln * cvss_medio_vuln * log1p(downloads_totais)

    Identifica também os pacotes-chave de cada comunidade (maior in-degree
    no grafo direcionado original; downloads como critério de desempate).
    """
    log.info("Cruzando comunidades com vulnerabilidades...")

    # in-degree calculado no grafo DIRECIONADO original (nº de dependentes)
    in_deg = dict(G_dir.in_degree())

    # Agrupa nós por comunidade
    members: dict[int, list] = defaultdict(list)
    for node, cid in partition.items():
        members[cid].append(node)

    rows = []
    for cid, nodes in members.items():
        n_pkgs = len(nodes)
        cvss_vals = []
        downloads_total = 0
        n_vuln = 0

        for node in nodes:
            cvss = get_float(G_dir, node, "max_cvss")
            downloads_total += int(get_float(G_dir, node, "downloads"))
            if cvss > 0:
                n_vuln += 1
                cvss_vals.append(cvss)

        frac_vuln    = n_vuln / n_pkgs if n_pkgs else 0.0
        cvss_mean    = float(np.mean(cvss_vals)) if cvss_vals else 0.0
        cvss_max     = float(np.max(cvss_vals)) if cvss_vals else 0.0

        # Risco: prevalência × gravidade × exposição (downloads)
        risk = frac_vuln * cvss_mean * np.log1p(downloads_total)

        # Pacotes-chave: ordena por in-degree, desempata por downloads
        ranked = sorted(
            nodes,
            key=lambda x: (in_deg.get(x, 0),
                           get_float(G_dir, x, "downloads")),
            reverse=True,
        )
        top_members = []
        for m in ranked[:TOP_MEMBERS]:
            top_members.append({
                "package":   m,
                "in_degree": in_deg.get(m, 0),
                "downloads": int(get_float(G_dir, m, "downloads")),
                "max_cvss":  get_float(G_dir, m, "max_cvss"),
                "vulnerable": get_float(G_dir, m, "max_cvss") > 0,
            })

        rows.append({
            "community_id":     int(cid),
            "n_packages":       n_pkgs,
            "n_vulnerable":     n_vuln,
            "frac_vulnerable":  round(frac_vuln, 4),
            "cvss_mean":        round(cvss_mean, 2),
            "cvss_max":         round(cvss_max, 2),
            "total_downloads":  downloads_total,
            "risk_score":       round(float(risk), 3),
            "top_members":      top_members,
        })

    rows.sort(key=lambda x: x["risk_score"], reverse=True)

    log.info(f"Top {TOP_N_RISK} comunidades por risco:")
    for r in rows[:TOP_N_RISK]:
        head = ", ".join(m["package"] for m in r["top_members"][:3])
        log.info(
            f"  C{r['community_id']:<5} risco={r['risk_score']:>7.2f} | "
            f"{r['n_packages']:>5} pkgs | vuln={r['n_vulnerable']:>4} "
            f"({100*r['frac_vulnerable']:.1f}%) | CVSS_méd={r['cvss_mean']:.1f} | "
            f"dl={r['total_downloads']/1e6:.0f}M | {head}"
        )
    return rows


# =============================================
#  ANOTAÇÃO E SALVAMENTO DO GRAFO
# =============================================

def annotate_and_save(G_dir: nx.DiGraph, partition: dict, path: Path):
    """
    Adiciona o atributo `community` a cada nó (nós fora do maior WCC
    recebem -1) e salva o grafo direcionado anotado em GraphML.
    """
    log.info("Anotando nós com o id de comunidade...")
    for node in G_dir.nodes():
        G_dir.nodes[node]["community"] = int(partition.get(node, -1))

    nx.write_graphml(G_dir, path)
    log.info(f"  [OK] {path} ({path.stat().st_size / 1e6:.1f} MB)")


# =============================================
#  GRÁFICO 1 — DISTRIBUIÇÃO DE TAMANHOS
# =============================================

def plot_size_distribution(sizes: Counter):
    """Histograma da distribuição de tamanhos das comunidades (escala log)."""
    size_values = sorted(sizes.values(), reverse=True)

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Distribuição de Tamanhos das Comunidades (Louvain)",
                 fontsize=14, y=1.02)

    # -- Painel esquerdo: histograma log-binned -----------------------------
    ax = axes[0]
    max_size = max(size_values)
    bins = np.logspace(0, np.log10(max_size) + 0.1, 30)
    ax.hist(size_values, bins=bins, color=ACCENT, alpha=0.85,
            edgecolor="#30363d", linewidth=0.5)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Tamanho da comunidade (nº de pacotes)")
    ax.set_ylabel("Nº de comunidades")
    ax.set_title("Histograma (log-log)")
    ax.grid(True, which="both", alpha=0.4)

    # -- Painel direito: tamanho das 25 maiores comunidades -----------------
    ax2 = axes[1]
    top = size_values[:25]
    x = np.arange(len(top))
    ax2.bar(x, top, color=ACCENT2, alpha=0.85,
            edgecolor="#30363d", linewidth=0.5)
    ax2.set_xlabel("Ranking da comunidade (por tamanho)")
    ax2.set_ylabel("Nº de pacotes")
    ax2.set_title(f"25 maiores comunidades  (total: {len(size_values):,})")
    ax2.grid(True, axis="y", alpha=0.4)
    ax2.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))

    plt.tight_layout()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = FIGURES_DIR / "communities_size_distribution.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# =============================================
#  GRÁFICO 2 — RISCO DAS TOP COMUNIDADES
# =============================================

def plot_community_risk(rows: list[dict]):
    """Barras horizontais das top comunidades por risco, coloridas por CVSS médio."""
    top = rows[:TOP_N_RISK]
    if not top:
        return

    labels = [
        f"C{r['community_id']} ({r['n_packages']}p)"
        for r in reversed(top)
    ]
    risks   = [r["risk_score"] for r in reversed(top)]
    cvsses  = [r["cvss_mean"] for r in reversed(top)]

    cmap   = plt.cm.RdYlGn_r
    norm   = plt.Normalize(vmin=0, vmax=10)
    colors = [cmap(norm(c)) for c in cvsses]

    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.barh(labels, risks, color=colors, height=0.66)

    for bar, r in zip(bars, reversed(top)):
        head = ", ".join(m["package"] for m in r["top_members"][:3])
        txt = (f"vuln={r['n_vulnerable']}/{r['n_packages']} "
               f"({100*r['frac_vulnerable']:.0f}%)  "
               f"dl={r['total_downloads']/1e6:.0f}M  ›  {head}")
        ax.text(bar.get_width() + max(risks) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                txt, va="center", ha="left", fontsize=7.5, color="#c9d1d9")

    ax.set_xlabel("Risco da comunidade  =  frac_vuln × CVSS_médio × log(downloads+1)")
    ax.set_title(
        f"Top {TOP_N_RISK} Comunidades por Risco de Vulnerabilidade\n"
        "(prevalência da falha × gravidade × exposição real)"
    )
    ax.set_xlim(0, max(risks) * 1.55)
    ax.grid(True, axis="x", alpha=0.4)

    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    cbar = plt.colorbar(sm, ax=ax, fraction=0.02, pad=0.02)
    cbar.set_label("CVSS médio (pacotes vulneráveis)", color="#c9d1d9")
    cbar.ax.yaxis.set_tick_params(color="#8b949e")

    plt.tight_layout()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = FIGURES_DIR / "communities_risk.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# =============================================
#  GRÁFICO 3 — REDE DAS TOP COMUNIDADES DE RISCO
# =============================================

def plot_communities_network(G_dir: nx.DiGraph, H: nx.Graph,
                             partition: dict, rows: list[dict],
                             n_communities: int = 6,
                             max_nodes_per_comm: int = 60):
    """
    Visualiza o subgrafo formado pelas top comunidades de risco.

    Como o grafo inteiro é grande demais para plotar (~40k nós), amostramos:
      - selecionamos as `n_communities` comunidades de maior risco;
      - de cada uma, mantemos no máximo `max_nodes_per_comm` nós mais
        relevantes (por grau no subgrafo não-direcionado), SEMPRE incluindo
        os pacotes vulneráveis;
      - layout: spring_layout (Fruchterman-Reingold) com seed fixo.

    Codificação visual:
      - cor   = comunidade
      - tamanho = log(downloads)
      - borda vermelha + estrela = pacote vulnerável (max_cvss > 0)
    """
    log.info("Gerando visualização da rede das top comunidades de risco...")
    top_cids = [r["community_id"] for r in rows[:n_communities]]

    deg_H = dict(H.degree())
    selected = []
    comm_palette = {}
    palette = plt.cm.tab10(np.linspace(0, 1, max(len(top_cids), 1)))

    for idx, cid in enumerate(top_cids):
        comm_palette[cid] = palette[idx]
        nodes = [n for n in H.nodes() if partition.get(n) == cid]
        # vulneráveis primeiro, depois maior grau
        nodes.sort(key=lambda x: (get_float(G_dir, x, "max_cvss") > 0,
                                  deg_H.get(x, 0)), reverse=True)
        selected.extend(nodes[:max_nodes_per_comm])

    sub = H.subgraph(selected)
    log.info(f"  Subgrafo de plotagem: {sub.number_of_nodes()} nós | "
             f"{sub.number_of_edges()} arestas | {len(top_cids)} comunidades")

    # Layout determinístico
    pos = nx.spring_layout(sub, seed=SEED, k=0.35, iterations=60)

    # Atributos visuais
    node_colors, node_sizes, vuln_nodes, vuln_pos = [], [], [], []
    for n in sub.nodes():
        cid = partition.get(n)
        node_colors.append(comm_palette.get(cid, (0.5, 0.5, 0.5, 1.0)))
        dl = get_float(G_dir, n, "downloads")
        node_sizes.append(20 + 12 * np.log1p(dl))
        if get_float(G_dir, n, "max_cvss") > 0:
            vuln_nodes.append(n)

    fig, ax = plt.subplots(figsize=(14, 11))
    ax.set_facecolor("#0d1117")

    nx.draw_networkx_edges(sub, pos, ax=ax, edge_color="#30363d",
                           width=0.4, alpha=0.5)
    nx.draw_networkx_nodes(sub, pos, ax=ax, node_color=node_colors,
                           node_size=node_sizes, linewidths=0.3,
                           edgecolors="#0d1117")
    # Destaca vulneráveis com borda vermelha
    if vuln_nodes:
        vsizes = [20 + 12 * np.log1p(get_float(G_dir, n, "downloads"))
                  for n in vuln_nodes]
        nx.draw_networkx_nodes(sub, pos, nodelist=vuln_nodes, ax=ax,
                               node_color="none", node_size=vsizes,
                               linewidths=1.4, edgecolors=ACCENT3)

    # Rotula os pacotes mais relevantes (maior grau) de cada comunidade
    labels = {}
    for cid in top_cids:
        comm_nodes = [n for n in sub.nodes() if partition.get(n) == cid]
        comm_nodes.sort(key=lambda x: deg_H.get(x, 0), reverse=True)
        for n in comm_nodes[:3]:
            labels[n] = n
    nx.draw_networkx_labels(sub, pos, labels=labels, ax=ax,
                            font_size=7, font_color="#f0f6fc",
                            font_family="monospace")

    # Legenda de comunidades
    from matplotlib.lines import Line2D
    legend_items = []
    for cid in top_cids:
        r = next(x for x in rows if x["community_id"] == cid)
        legend_items.append(Line2D(
            [0], [0], marker="o", color="none",
            markerfacecolor=comm_palette[cid], markersize=9,
            label=f"C{cid}: {r['n_packages']}p, "
                  f"{100*r['frac_vulnerable']:.0f}% vuln, risco={r['risk_score']:.1f}"
        ))
    legend_items.append(Line2D(
        [0], [0], marker="o", color="none", markerfacecolor="none",
        markeredgecolor=ACCENT3, markeredgewidth=1.5, markersize=10,
        label="borda = pacote vulnerável"
    ))
    ax.legend(handles=legend_items, loc="upper left", fontsize=8,
              framealpha=0.9)

    ax.set_title(
        f"Rede das Top {n_communities} Comunidades de Risco\n"
        "cor = comunidade · tamanho = log(downloads) · borda laranja = vulnerável",
        fontsize=13
    )
    ax.axis("off")
    plt.tight_layout()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = FIGURES_DIR / "communities_network.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# =============================================
#  SALVAR ESTATÍSTICAS EM JSON
# =============================================

def save_stats(n_communities: int, modularity: float,
               sizes: Counter, rows: list[dict]):
    size_values = sorted(sizes.values(), reverse=True)
    stats = {
        "n_communities":        n_communities,
        "modularity":           round(modularity, 4),
        "largest_community":    max(size_values),
        "smallest_community":   min(size_values),
        "median_community_size": int(np.median(size_values)),
        "mean_community_size":  round(float(np.mean(size_values)), 2),
        "top_risk_communities": rows[:TOP_N_RISK],
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    log.info(f"  [OK] {OUTPUT_JSON}")


# =============================================
#  MAIN
# =============================================

def main():
    random.seed(SEED)
    np.random.seed(SEED)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    log.info("=" * 62)
    log.info("DETECÇÃO DE COMUNIDADES — GRAFO DE DEPENDÊNCIAS PyPI")
    log.info("=" * 62)

    # 1) Carga + conversão p/ não-direcionado no maior WCC
    G_dir = load_graph(INPUT_GRAPHML)
    H = to_undirected_largest_wcc(G_dir)

    # 2) Detecção de comunidades (Louvain)
    partition, modularity = detect_communities(H)
    sizes, _ = community_size_distribution(partition)
    n_communities = len(sizes)

    # 3) Análise de risco por comunidade
    rows = analyze_community_risk(G_dir, H, partition)

    # 4) Anota e salva o grafo
    annotate_and_save(G_dir, partition, OUTPUT_GRAPHML)

    # 5) Figuras
    log.info("Gerando visualizações...")
    plot_size_distribution(sizes)
    plot_community_risk(rows)
    plot_communities_network(G_dir, H, partition, rows)

    # 6) JSON de estatísticas
    save_stats(n_communities, modularity, sizes, rows)

    # --- Resumo no console ---
    print("\n" + "=" * 62)
    print("[OK] Detecção de comunidades concluída!")
    print(f"   Comunidades detectadas : {n_communities:,}")
    print(f"   Modularidade global Q  : {modularity:.4f}")
    print("\n   Top 5 comunidades de risco:")
    for r in rows[:5]:
        head = ", ".join(m["package"] for m in r["top_members"][:3])
        print(
            f"   C{r['community_id']:<5} risco={r['risk_score']:>7.2f} | "
            f"{r['n_packages']:>5}p | vuln={r['n_vulnerable']} "
            f"({100*r['frac_vulnerable']:.1f}%) | CVSS_méd={r['cvss_mean']:.1f} | "
            f"{head}"
        )
    print("=" * 62)


if __name__ == "__main__":
    main()
