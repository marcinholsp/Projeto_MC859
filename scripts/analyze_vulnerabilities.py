"""
analyze_vulnerabilities.py
==========================
Analisa propagação de vulnerabilidades no grafo de dependências PyPI usando
o modelo Independent Cascade (IC) ponderado por downloads.

Motivação:
    Um pacote com in-degree 1.000 NÃO é necessariamente crítico se nenhum
    dos seus 1.000 dependentes é efetivamente usado. O modelo IC pondera
    a probabilidade de propagação pelos downloads reais de cada pacote,
    separando centralidade estrutural de impacto prático.

Modelo IC (Independent Cascade):
    - Grafo reverso: aresta B→A (A depende de B na direção original)
    - Quando B é comprometido, infecta A com probabilidade p(B→A):
        p(B→A) = log1p(downloads_B) / Σ log1p(downloads_dep) para dep em A
    - Rodadas Monte Carlo: N_SIMS simulações por pacote vulnerável
    - Resultado: alcance_ic = contagem média de infectados
                 active_downloads = soma média dos downloads infectados

Score de criticidade (atende ao feedback do professor):
    risk = CVSS × log1p(active_downloads_ic) × log1p(downloads_próprios)

    - CVSS           : gravidade real da vulnerabilidade
    - active_downloads_ic : downloads acumulados dos pacotes que REALMENTE
                       seriam afetados (ponderados pela probabilidade IC)
    - downloads_próprios  : relevância real do pacote no ecossistema

Saída:
    data/vuln_stats.json
    figures/vuln_risk_scores.png
    figures/vuln_downloads_vs_cvss.png
    figures/vuln_ic_reach_distribution.png
    figures/vuln_cascade_example.png

Uso:
    pip install networkx matplotlib numpy cvss
    python scripts/analyze_vulnerabilities.py
"""

import json
import logging
import random
from collections import deque
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import networkx as nx

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
DATA_DIR      = PROJECT_ROOT / "data"
FIGURES_DIR   = PROJECT_ROOT / "assets"

INPUT_GRAPHML = DATA_DIR / "pypi_dependency_graph_vuln.graphml"
OUTPUT_JSON   = DATA_DIR / "vuln_stats.json"
FIG_DPI       = 150

N_SIMS = 500   # simulações Monte Carlo por pacote

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------
#  ESTILO GLOBAL
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
ACCENT  = "#58a6ff"
ACCENT2 = "#3fb950"
ACCENT3 = "#f78166"
ACCENT4 = "#d2a8ff"


# ---------------------------------------------
#  CARGA
# ---------------------------------------------

def load_graph(path: Path) -> nx.DiGraph:
    log.info(f"Carregando grafo: {path} ({path.stat().st_size / 1e6:.1f} MB)")
    G = nx.read_graphml(path)
    log.info(f"  {G.number_of_nodes():,} nós | {G.number_of_edges():,} arestas")
    return G


def get_float(G, node, attr, default=0.0):
    v = G.nodes[node].get(attr, default)
    try:
        return float(v) if v not in (None, "") else default
    except (ValueError, TypeError):
        return default


# ---------------------------------------------
#  MODELO IC — PRÉ-COMPUTAÇÃO DE PROBABILIDADES
# ---------------------------------------------

def compute_ic_probabilities(G: nx.DiGraph) -> dict[tuple, float]:
    """
    Para cada aresta A→B no grafo original (A depende de B),
    calcula p(B→A) no grafo reverso:

        p(B→A) = log1p(downloads_B) / Σ_{dep ∈ deps(A)} log1p(downloads_dep)

    Interpreta: fração do "peso de dependência" de A que vem de B.
    Se B for a única dependência de A: p ≈ 1.
    Se B for uma entre muitas dependências populares de A: p é pequeno.
    """
    log.info("Pré-computando probabilidades IC ponderadas por downloads...")
    # Para cada nó A, calcula a soma dos log1p(downloads) de suas dependências
    dep_weight_sum: dict[str, float] = {}
    for a in G.nodes():
        total = sum(
            np.log1p(get_float(G, b, "downloads"))
            for b in G.successors(a)   # b = dependência de a
        )
        dep_weight_sum[a] = max(total, 1.0)   # evita divisão por zero

    # Probabilidades: para cada aresta A→B, p(B infecta A) no grafo reverso
    probs: dict[tuple, float] = {}
    for a, b in G.edges():
        w_b = np.log1p(get_float(G, b, "downloads"))
        probs[(b, a)] = min(1.0, w_b / dep_weight_sum[a])

    log.info(f"  {len(probs):,} probabilidades de aresta calculadas.")
    return probs


# ---------------------------------------------
#  SIMULAÇÃO IC — MONTE CARLO
# ---------------------------------------------

def ic_simulate(source: str, G_rev: nx.DiGraph,
                probs: dict[tuple, float],
                downloads: dict[str, int],
                n_sims: int = N_SIMS) -> dict:
    """
    Roda n_sims simulações do modelo IC a partir de `source` no grafo reverso.

    Retorna:
        reach_mean        : número médio de pacotes infectados (excl. source)
        active_dl_mean    : soma média dos downloads dos infectados (excl. source)
        reach_std         : desvio padrão do alcance
        bfs_reach         : alcance determinístico (BFS completo, para comparação)
        bfs_active_dl     : downloads acumulados do BFS completo
    """
    rng = random.Random()
    reach_list = []
    dl_list    = []

    for _ in range(n_sims):
        infected = {source}
        queue    = deque([source])
        total_dl = 0
        while queue:
            node = queue.popleft()
            for neighbor in G_rev.neighbors(node):
                if neighbor not in infected:
                    p = probs.get((node, neighbor), 0.0)
                    if rng.random() < p:
                        infected.add(neighbor)
                        total_dl += downloads.get(neighbor, 0)
                        queue.append(neighbor)
        reach_list.append(len(infected) - 1)
        dl_list.append(total_dl)

    # BFS determinístico (alcance máximo possível)
    visited  = {source}
    bfs_q    = deque([source])
    bfs_dl   = 0
    while bfs_q:
        node = bfs_q.popleft()
        for nb in G_rev.neighbors(node):
            if nb not in visited:
                visited.add(nb)
                bfs_dl += downloads.get(nb, 0)
                bfs_q.append(nb)
    bfs_reach = len(visited) - 1

    return {
        "reach_mean":     float(np.mean(reach_list)),
        "reach_std":      float(np.std(reach_list)),
        "active_dl_mean": float(np.mean(dl_list)),
        "bfs_reach":      bfs_reach,
        "bfs_active_dl":  bfs_dl,
    }


# ---------------------------------------------
#  MÉTRICAS PRINCIPAIS
# ---------------------------------------------

def compute_all_metrics(G: nx.DiGraph) -> dict:
    downloads = {n: int(get_float(G, n, "downloads")) for n in G.nodes()}
    in_deg    = dict(G.in_degree())
    G_rev     = G.reverse(copy=False)
    probs     = compute_ic_probabilities(G)

    vulnerable = [
        n for n in G.nodes()
        if get_float(G, n, "max_cvss") > 0
    ]
    log.info(f"{len(vulnerable):,} pacotes vulneráveis de {G.number_of_nodes():,}")

    rows = []
    for i, node in enumerate(vulnerable):
        if (i + 1) % 50 == 0:
            log.info(f"  IC: {i+1}/{len(vulnerable)} pacotes processados...")

        cvss      = get_float(G, node, "max_cvss")
        vuln_cnt  = int(get_float(G, node, "vuln_count"))
        vuln_ids  = G.nodes[node].get("vuln_ids", "")
        own_dl    = downloads.get(node, 0)

        ic = ic_simulate(node, G_rev, probs, downloads)

        # Risk score: gravidade × downloads afetados pelo IC × próprio uso
        risk = cvss * np.log1p(ic["active_dl_mean"]) * np.log1p(own_dl)

        rows.append({
            "package":        node,
            "cvss":           cvss,
            "vuln_count":     vuln_cnt,
            "vuln_ids":       vuln_ids,
            "own_downloads":  own_dl,
            "ic_reach":       round(ic["reach_mean"], 1),
            "ic_reach_std":   round(ic["reach_std"], 1),
            "ic_active_dl":   round(ic["active_dl_mean"]),
            "bfs_reach":      ic["bfs_reach"],
            "bfs_active_dl":  ic["bfs_active_dl"],
            "risk_score":     round(risk, 2),
        })

    rows.sort(key=lambda x: x["risk_score"], reverse=True)

    log.info("Top 10 por risk_score (IC + downloads):")
    for r in rows[:10]:
        log.info(
            f"  {r['package']:<30} CVSS={r['cvss']}  "
            f"own_dl={r['own_downloads']:,}  "
            f"ic_reach={r['ic_reach']:.0f}  "
            f"ic_dl={r['ic_active_dl']:,}  "
            f"risk={r['risk_score']}"
        )

    return {
        "total_nodes":      G.number_of_nodes(),
        "vulnerable_nodes": len(vulnerable),
        "pct_vulnerable":   round(100 * len(vulnerable) / G.number_of_nodes(), 1),
        "top_risks":        rows[:50],
        "_all_rows":        rows,
    }


# ---------------------------------------------
#  GRÁFICO 1 — TOP 20 RISCO IC
# ---------------------------------------------

def plot_risk_scores(metrics: dict):
    rows = metrics["_all_rows"][:20]
    if not rows:
        return

    names   = [r["package"] for r in reversed(rows)]
    risks   = [r["risk_score"] for r in reversed(rows)]
    cvsses  = [r["cvss"] for r in reversed(rows)]

    cmap   = plt.cm.RdYlGn_r
    norm   = plt.Normalize(vmin=0, vmax=10)
    colors = [cmap(norm(c)) for c in cvsses]

    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.barh(names, risks, color=colors, height=0.65)

    for bar, r, row in zip(bars, risks, reversed(rows)):
        txt = (f"CVSS={row['cvss']}  "
               f"dl_próprios={row['own_downloads']/1e6:.0f}M  "
               f"dl_afetados={row['ic_active_dl']/1e6:.0f}M")
        ax.text(bar.get_width() + max(risks) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                txt, va="center", ha="left", fontsize=7.5, color="#c9d1d9")

    ax.set_xlabel(
        "Risk Score  =  CVSS × log(downloads afetados pelo IC + 1)"
        " × log(downloads próprios + 1)"
    )
    ax.set_title(
        "Top 20 Pacotes por Risco — Modelo IC ponderado por downloads\n"
        "(gravidade × uso real dos dependentes × uso real do pacote)"
    )
    ax.set_xlim(0, max(risks) * 1.45)
    ax.grid(True, axis="x", alpha=0.4)

    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    cbar = plt.colorbar(sm, ax=ax, fraction=0.02, pad=0.02)
    cbar.set_label("CVSS Score", color="#c9d1d9")
    cbar.ax.yaxis.set_tick_params(color="#8b949e")

    plt.tight_layout()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = FIGURES_DIR / "vuln_risk_scores.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# ---------------------------------------------
#  GRÁFICO 2 — IC reach vs BFS reach (impacto dos downloads)
# ---------------------------------------------

def plot_ic_vs_bfs(metrics: dict):
    """
    Compara alcance BFS (estrutural) vs alcance IC médio (ponderado por downloads).
    Mostra que pacotes centrais mas pouco usados têm IC << BFS.
    """
    rows = metrics["_all_rows"]
    if not rows:
        return

    bfs_reach = [r["bfs_reach"] for r in rows]
    ic_reach  = [r["ic_reach"] for r in rows]
    own_dl    = [r["own_downloads"] for r in rows]

    fig, ax = plt.subplots(figsize=(9, 7))

    sc = ax.scatter(bfs_reach, ic_reach,
                    c=np.log1p(own_dl), cmap="YlOrRd",
                    alpha=0.6, s=15, linewidths=0)
    ax.plot([0, max(bfs_reach)], [0, max(bfs_reach)],
            color="#8b949e", linestyle="--", linewidth=0.8,
            alpha=0.7, label="IC = BFS (linha de referência)")

    ax.set_xlabel("Alcance BFS (estrutural — sem ponderação)")
    ax.set_ylabel("Alcance IC médio (ponderado por downloads)")
    ax.set_title(
        "BFS vs Modelo IC: alcance estrutural × alcance ponderado por uso real\n"
        "Pontos abaixo da diagonal = alta centralidade estrutural, baixo uso real"
    )
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

    cbar = plt.colorbar(sc, ax=ax)
    cbar.set_label("log(downloads próprios)", color="#c9d1d9")
    cbar.ax.yaxis.set_tick_params(color="#8b949e")

    # Anota top 5 por BFS que têm IC muito menor (alta discrepância)
    top_disc = sorted(rows,
                      key=lambda x: x["bfs_reach"] - x["ic_reach"],
                      reverse=True)[:5]
    for r in top_disc:
        ax.annotate(r["package"],
                    xy=(r["bfs_reach"], r["ic_reach"]),
                    xytext=(r["bfs_reach"] * 0.85, r["ic_reach"] + 5),
                    fontsize=7, color=ACCENT4,
                    arrowprops=dict(arrowstyle="->", color=ACCENT4, lw=0.7))

    plt.tight_layout()
    out = FIGURES_DIR / "vuln_ic_vs_bfs.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# ---------------------------------------------
#  GRÁFICO 3 — Downloads afetados × CVSS (scatter)
# ---------------------------------------------

def plot_downloads_vs_cvss(metrics: dict):
    rows = metrics["_all_rows"]
    if not rows:
        return

    ic_dl  = [r["ic_active_dl"] / 1e6 for r in rows]    # em milhões
    cvsses = [r["cvss"] for r in rows]
    risks  = [r["risk_score"] for r in rows]

    fig, ax = plt.subplots(figsize=(9, 6))
    sc = ax.scatter(ic_dl, cvsses, c=risks, cmap="plasma",
                    alpha=0.6, s=18, linewidths=0)

    ax.set_xscale("symlog", linthresh=1)
    ax.set_xlabel("Downloads mensais afetados via IC (milhões, escala log)")
    ax.set_ylabel("CVSS Score Máximo")
    ax.set_title(
        "Downloads Afetados pelo IC × Severidade CVSS\n"
        "(cor = risk score — combina gravidade + uso real)"
    )
    ax.axhline(9.0, color=ACCENT3,   linestyle="--", lw=0.8, alpha=0.7, label="Crítico ≥ 9.0")
    ax.axhline(7.0, color="#f0883e", linestyle="--", lw=0.8, alpha=0.7, label="Alto ≥ 7.0")
    ax.legend(fontsize=9)
    ax.grid(True, which="both", alpha=0.3)

    cbar = plt.colorbar(sc, ax=ax)
    cbar.set_label("Risk Score", color="#c9d1d9")
    cbar.ax.yaxis.set_tick_params(color="#8b949e")

    top5 = sorted(rows, key=lambda x: x["risk_score"], reverse=True)[:5]
    for r in top5:
        ax.annotate(r["package"],
                    xy=(r["ic_active_dl"] / 1e6, r["cvss"]),
                    xytext=(r["ic_active_dl"] / 1e6 * 1.5 + 0.1, r["cvss"] + 0.2),
                    fontsize=7.5, color=ACCENT4,
                    arrowprops=dict(arrowstyle="->", color=ACCENT4, lw=0.8))

    plt.tight_layout()
    out = FIGURES_DIR / "vuln_downloads_vs_cvss.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# ---------------------------------------------
#  GRÁFICO 4 — Cascata do pacote mais crítico
# ---------------------------------------------

def plot_cascade_example(G: nx.DiGraph, metrics: dict,
                         probs: dict[tuple, float]):
    rows = metrics["_all_rows"]
    if not rows:
        return

    source    = rows[0]["package"]
    downloads = {n: int(get_float(G, n, "downloads")) for n in G.nodes()}
    G_rev     = G.reverse(copy=False)

    log.info(f"Gerando cascata IC para: {source}")

    # Coleta distribuição de profundidade em múltiplas simulações
    N = 200
    depth_totals: dict[int, list] = {}
    dl_totals:    dict[int, list] = {}

    for _ in range(N):
        infected = {source: 0}   # node → depth
        queue    = deque([(source, 0)])
        sim_depth_dl: dict[int, int] = {0: 0}
        rng = random.Random()
        while queue:
            node, depth = queue.popleft()
            for nb in G_rev.neighbors(node):
                if nb not in infected:
                    p = probs.get((node, nb), 0.0)
                    if rng.random() < p:
                        infected[nb] = depth + 1
                        sim_depth_dl[depth + 1] = (
                            sim_depth_dl.get(depth + 1, 0)
                            + downloads.get(nb, 0)
                        )
                        queue.append((nb, depth + 1))
        for d, dl in sim_depth_dl.items():
            depth_totals.setdefault(d, []).append(
                sum(1 for v in infected.values() if v == d)
            )
            dl_totals.setdefault(d, []).append(dl)

    depths = sorted(depth_totals)
    mean_counts = [np.mean(depth_totals[d]) for d in depths]
    mean_dls    = [np.mean(dl_totals[d]) / 1e6 for d in depths]   # em milhões
    cum_counts  = np.cumsum(mean_counts)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle(
        f"Cascata IC — Pacote: '{source}'\n"
        f"CVSS={rows[0]['cvss']}  |  downloads próprios={rows[0]['own_downloads']/1e6:.0f}M  "
        f"|  IC médio={rows[0]['ic_reach']:.0f} pacotes afetados",
        fontsize=12
    )

    # Painel 1: pacotes e downloads afetados por nível
    x     = np.arange(len(depths))
    width = 0.4
    ax1.bar(x - width/2, mean_counts, width, color=ACCENT,  alpha=0.85,
            edgecolor="#30363d", lw=0.5, label="Pacotes afetados (média IC)")
    ax1b = ax1.twinx()
    ax1b.bar(x + width/2, mean_dls, width, color=ACCENT3, alpha=0.85,
             edgecolor="#30363d", lw=0.5, label="Downloads afetados (M)")
    ax1.set_xticks(x)
    ax1.set_xticklabels([str(d) for d in depths])
    ax1.set_xlabel("Profundidade (hops)")
    ax1.set_ylabel("Pacotes afetados (média)")
    ax1b.set_ylabel("Downloads afetados (milhões)")
    ax1b.tick_params(colors="#8b949e")
    ax1b.yaxis.label.set_color("#c9d1d9")
    ax1.set_title("Novos afetados por profundidade")
    ax1.legend(loc="upper right", fontsize=8)
    ax1b.legend(loc="upper center", fontsize=8)
    ax1.grid(True, axis="y", alpha=0.4)
    ax1.set_facecolor("#161b22")

    # Painel 2: acumulado
    ax2.plot(depths, cum_counts, color=ACCENT, lw=2, marker="o", ms=4, label="IC (Monte Carlo)")
    ax2.fill_between(depths, cum_counts, alpha=0.15, color=ACCENT)
    # BFS determinístico para comparação
    bfs_reach = rows[0]["bfs_reach"]
    ax2.axhline(bfs_reach, color="#8b949e", linestyle="--", lw=0.9,
                alpha=0.7, label=f"BFS máximo ({bfs_reach:,})")
    ax2.set_xlabel("Profundidade")
    ax2.set_ylabel("Total acumulado de pacotes infectados")
    ax2.set_title("Propagação acumulada: IC vs BFS")
    ax2.legend(fontsize=9)
    ax2.grid(True, alpha=0.4)
    ax2.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax2.set_facecolor("#161b22")

    plt.tight_layout()
    out = FIGURES_DIR / "vuln_cascade_example.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# ---------------------------------------------
#  MAIN
# ---------------------------------------------

def main():
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    log.info("=" * 60)
    log.info("ANÁLISE IC — PROPAGAÇÃO PONDERADA POR DOWNLOADS")
    log.info("=" * 60)

    G       = load_graph(INPUT_GRAPHML)
    probs   = compute_ic_probabilities(G)
    metrics = compute_all_metrics(G)

    log.info("Gerando visualizações...")
    plot_risk_scores(metrics)
    plot_ic_vs_bfs(metrics)
    plot_downloads_vs_cvss(metrics)
    plot_cascade_example(G, metrics, probs)

    # Salva JSON
    clean = {k: v for k, v in metrics.items() if not k.startswith("_")}
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(clean, f, ensure_ascii=False, indent=2)
    log.info(f"  [OK] {OUTPUT_JSON}")

    print("\n[OK] Análise IC concluída!")
    print(f"   Pacotes vulneráveis: {metrics['vulnerable_nodes']}/{metrics['total_nodes']}")
    print("\n   Top 5 por risk score (IC + downloads):")
    for r in metrics["top_risks"][:5]:
        print(
            f"   {r['package']:<30} "
            f"CVSS={r['cvss']}  "
            f"own={r['own_downloads']/1e6:.0f}M  "
            f"ic_dl={r['ic_active_dl']/1e6:.0f}M  "
            f"risk={r['risk_score']}"
        )


if __name__ == "__main__":
    main()
