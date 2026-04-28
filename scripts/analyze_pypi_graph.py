"""
analyze_pypi_graph.py
=====================
Carrega o grafo gerado por build_pypi_graph.py e produz:
  - Métricas textuais completas
  - degree_distribution.png  (distribuição de graus)
  - scc_distribution.png     (distribuição dos tamanhos das CFCs)
  - top_packages.png         (top 20 mais dependidos)
  - stats.json               (métricas em JSON para o documento)

Uso:
    pip install networkx matplotlib numpy
    python analyze_pypi_graph.py
"""

import json
import logging
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import networkx as nx

# ---------------------------------------------
#  CONFIGURAÇÕES
# ---------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR     = PROJECT_ROOT / "data"
FIGURES_DIR  = PROJECT_ROOT / "assets"

INPUT_FILE   = DATA_DIR / "pypi_dependency_graph.graphml"   # ou .gexf
OUTPUT_JSON  = DATA_DIR / "stats.json"
FIG_DPI      = 150

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------
#  ESTILO GLOBAL DOS GRÁFICOS
# ---------------------------------------------
plt.rcParams.update({
    "figure.facecolor":  "#0d1117",   # fundo escuro (estilo GitHub dark)
    "axes.facecolor":    "#161b22",
    "axes.edgecolor":    "#30363d",
    "axes.labelcolor":   "#c9d1d9",
    "axes.titlecolor":   "#f0f6fc",
    "axes.titlesize":    13,
    "axes.labelsize":    11,
    "xtick.color":       "#8b949e",
    "ytick.color":       "#8b949e",
    "grid.color":        "#21262d",
    "grid.linestyle":    "--",
    "grid.linewidth":    0.6,
    "text.color":        "#c9d1d9",
    "legend.facecolor":  "#161b22",
    "legend.edgecolor":  "#30363d",
    "font.family":       "monospace",
})

ACCENT   = "#58a6ff"   # azul GitHub
ACCENT2  = "#3fb950"   # verde
ACCENT3  = "#f78166"   # vermelho/laranja


# ---------------------------------------------
#  CARREGAMENTO
# ---------------------------------------------

def load_graph(path: str) -> nx.DiGraph:
    p = Path(path)
    log.info(f"Carregando grafo de {p} ({p.stat().st_size / 1e6:.1f} MB)...")
    if p.suffix == ".graphml":
        G = nx.read_graphml(p)
    elif p.suffix == ".gexf":
        G = nx.read_gexf(p)
    else:
        raise ValueError(f"Formato não suportado: {p.suffix}")
    log.info(f"Grafo carregado: {G.number_of_nodes():,} nós, {G.number_of_edges():,} arestas")
    return G


# ---------------------------------------------
#  MÉTRICAS
# ---------------------------------------------

def compute_metrics(G: nx.DiGraph) -> dict:
    n = G.number_of_nodes()
    m = G.number_of_edges()

    # Graus (não-direcionado equivalente)
    degrees     = [d for _, d in G.degree()]
    in_degrees  = [d for _, d in G.in_degree()]
    out_degrees = [d for _, d in G.out_degree()]

    avg_degree     = np.mean(degrees)
    avg_in_degree  = np.mean(in_degrees)
    avg_out_degree = np.mean(out_degrees)
    max_in_degree  = max(in_degrees)
    max_out_degree = max(out_degrees)

    # CFCs
    sccs  = list(nx.strongly_connected_components(G))
    sizes = sorted([len(c) for c in sccs], reverse=True)

    # WCCs (componentes fracamente conexas)
    wccs       = list(nx.weakly_connected_components(G))
    wcc_sizes  = sorted([len(c) for c in wccs], reverse=True)

    # Top 20 por in-degree
    top_in = sorted(G.in_degree(), key=lambda x: x[1], reverse=True)[:20]

    metrics = {
        "n_vertices":        n,
        "n_arestas":         m,
        "grau_medio":        round(avg_degree, 2),
        "in_degree_medio":   round(avg_in_degree, 2),
        "out_degree_medio":  round(avg_out_degree, 2),
        "in_degree_max":     max_in_degree,
        "out_degree_max":    max_out_degree,
        "n_sccs":            len(sccs),
        "maior_scc":         sizes[0] if sizes else 0,
        "n_singletons_scc":  sizes.count(1),
        "n_wccs":            len(wccs),
        "maior_wcc":         wcc_sizes[0] if wcc_sizes else 0,
        "top_20_in_degree":  [(p, d) for p, d in top_in],
        "_degrees":          degrees,
        "_in_degrees":       in_degrees,
        "_scc_sizes":        sizes,
        "_wcc_sizes":        wcc_sizes,
    }

    # Log legível
    log.info("-" * 55)
    log.info("MÉTRICAS DO GRAFO")
    log.info(f"  Vértices              : {n:,}")
    log.info(f"  Arestas               : {m:,}")
    log.info(f"  Grau médio (total)    : {avg_degree:.2f}")
    log.info(f"  In-degree médio       : {avg_in_degree:.2f}")
    log.info(f"  Out-degree médio      : {avg_out_degree:.2f}")
    log.info(f"  In-degree máximo      : {max_in_degree}")
    log.info(f"  Out-degree máximo     : {max_out_degree}")
    log.info(f"  CFCs totais           : {len(sccs):,}")
    log.info(f"  Maior CFC (vértices)  : {sizes[0]:,}")
    log.info(f"  CFCs singleton        : {sizes.count(1):,}")
    log.info(f"  CCFs (fracas) totais  : {len(wccs):,}")
    log.info(f"  Maior CCF (vértices)  : {wcc_sizes[0]:,}")
    log.info("  Top 10 mais dependidos (in-degree):")
    for pkg, deg in top_in[:10]:
        log.info(f"    {pkg:<38} {deg:>5}")
    log.info("-" * 55)

    return metrics


# ---------------------------------------------
#  GRÁFICO 1 — DISTRIBUIÇÃO DE GRAUS
# ---------------------------------------------

def plot_degree_distribution(metrics: dict):
    in_deg  = metrics["_in_degrees"]
    out_deg = metrics["_degrees"]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("Distribuição de Graus — Grafo de Dependências PyPI",
                 fontsize=14, y=1.02)

    for ax, data, label, color in [
        (axes[0], in_deg,  "In-degree (# de dependentes)",  ACCENT),
        (axes[1], out_deg, "Grau total (in + out)",         ACCENT2),
    ]:
        # Histograma em escala log-log
        counts = Counter(data)
        xs = sorted(counts.keys())
        ys = [counts[x] for x in xs]

        ax.scatter(xs, ys, s=14, alpha=0.7, color=color, linewidths=0)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel(label)
        ax.set_ylabel("Frequência")
        ax.set_title(f"{label.split('(')[0].strip()}")
        ax.grid(True, which="both")
        ax.xaxis.set_major_formatter(ticker.LogFormatterSciNotation())

        # Linha de tendência (regressão linear em log-log)
        xs_arr = np.array(xs, dtype=float)
        ys_arr = np.array(ys, dtype=float)
        mask = (xs_arr > 0) & (ys_arr > 0)
        if mask.sum() > 2:
            coeffs = np.polyfit(np.log10(xs_arr[mask]), np.log10(ys_arr[mask]), 1)
            x_fit = np.logspace(np.log10(xs_arr[mask].min()),
                                np.log10(xs_arr[mask].max()), 100)
            y_fit = 10 ** np.polyval(coeffs, np.log10(x_fit))
            ax.plot(x_fit, y_fit, "--", color="#f0f6fc", linewidth=1,
                    alpha=0.5, label=f"slope ≈ {coeffs[0]:.2f}")
            ax.legend(fontsize=9)

    plt.tight_layout()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = FIGURES_DIR / "degree_distribution.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# ---------------------------------------------
#  GRÁFICO 2 — DISTRIBUIÇÃO DE TAMANHOS DAS CFCs
# ---------------------------------------------

def plot_scc_distribution(metrics: dict):
    sizes = metrics["_scc_sizes"]
    counts = Counter(sizes)

    # Log da tabela completa
    log.info("  Distribuição de tamanhos de CFC:")
    for k, cnt in sorted(counts.items()):
        log.info(f"    k={k:>6,}  →  {cnt:>6,} componentes")

    n_singletons  = counts.get(1, 0)
    non_singleton = {k: v for k, v in counts.items() if k > 1}

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Distribuição dos Tamanhos das CFCs\n"
                 "(Componentes Fortemente Conexas — grafo direcionado)", fontsize=13)

    # -- Painel esquerdo: todas as CFCs por tamanho ---------------------------
    ax = axes[0]
    all_ks   = sorted(counts.keys())
    all_vals = [counts[k] for k in all_ks]
    colors   = [ACCENT3 if k == 1 else ACCENT for k in all_ks]

    bars = ax.bar([str(k) for k in all_ks], all_vals, color=colors, width=0.6)
    for bar, val in zip(bars, all_vals):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(all_vals) * 0.01,
                f"{val:,}", ha="center", va="bottom", fontsize=9, color="#c9d1d9")

    ax.set_xlabel("Tamanho da CFC (k vértices)")
    ax.set_ylabel("Número de CFCs")
    ax.set_title("Todas as CFCs por tamanho")
    ax.grid(True, axis="y", alpha=0.4)

    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(facecolor=ACCENT3, label=f"Singletons (k=1): {n_singletons:,}"),
        Patch(facecolor=ACCENT,  label=f"Não-singletons: {sum(non_singleton.values())}"),
    ], fontsize=9)

    # -- Painel direito: zoom nas CFCs não-singleton --------------------------
    ax2 = axes[1]
    if non_singleton:
        ks   = sorted(non_singleton.keys())
        vals = [non_singleton[k] for k in ks]
        bars2 = ax2.bar([str(k) for k in ks], vals, color=ACCENT, width=0.5)
        for bar, val in zip(bars2, vals):
            ax2.text(bar.get_x() + bar.get_width() / 2,
                     bar.get_height() + 0.05,
                     f"{val}", ha="center", va="bottom", fontsize=10, color="#c9d1d9")
        ax2.set_xlabel("Tamanho da CFC (k vértices)")
        ax2.set_ylabel("Número de CFCs")
        ax2.set_title("CFCs com mais de 1 vértice (zoom)")
        ax2.set_ylim(0, max(vals) + 1)
        ax2.grid(True, axis="y", alpha=0.4)

        # Anota a maior CFC
        maior_k = ks[-1]
        ax2.annotate(
            f"Maior CFC\n{maior_k} vértices",
            xy=(len(ks) - 1, non_singleton[maior_k]),
            xytext=(max(0, len(ks) - 2), non_singleton[maior_k] + 0.4),
            fontsize=9, color=ACCENT2,
            arrowprops=dict(arrowstyle="->", color=ACCENT2),
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#21262d", edgecolor=ACCENT2),
        )
    else:
        ax2.text(0.5, 0.5, "Todas as CFCs são singletons\n(grafo é um DAG perfeito)",
                 ha="center", va="center", transform=ax2.transAxes,
                 fontsize=12, color="#8b949e")
        ax2.set_title("CFCs com mais de 1 vértice (zoom)")

    plt.tight_layout()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = FIGURES_DIR / "scc_distribution.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# ---------------------------------------------
#  GRÁFICO 3 — TOP 20 PACOTES MAIS DEPENDIDOS
# ---------------------------------------------

def plot_top_packages(metrics: dict):
    top = metrics["top_20_in_degree"]
    if not top:
        return

    names  = [p for p, _ in reversed(top)]
    values = [d for _, d in reversed(top)]

    fig, ax = plt.subplots(figsize=(10, 7))
    ax.set_title("Top 20 Pacotes Mais Dependidos (in-degree)")

    bars = ax.barh(names, values, color=ACCENT, alpha=0.85, height=0.65)

    # Rótulos nos bars
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", ha="left", fontsize=8, color="#c9d1d9")

    ax.set_xlabel("In-degree (número de pacotes que dependem diretamente)")
    ax.set_xlim(0, max(values) * 1.18)
    ax.grid(True, axis="x", alpha=0.4)
    ax.tick_params(axis="y", labelsize=9)

    plt.tight_layout()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = FIGURES_DIR / "top_packages.png"
    plt.savefig(out, dpi=FIG_DPI, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()
    log.info(f"  [OK] {out}")


# ---------------------------------------------
#  SALVAR JSON COM MÉTRICAS
# ---------------------------------------------

def save_stats(metrics: dict):
    # Remove listas grandes antes de serializar
    clean = {k: v for k, v in metrics.items() if not k.startswith("_")}
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(clean, f, ensure_ascii=False, indent=2)
    log.info(f"  [OK] {OUTPUT_JSON}")


# ---------------------------------------------
#  MAIN
# ---------------------------------------------

def main():
    log.info("=" * 55)
    log.info("ANÁLISE DO GRAFO DE DEPENDÊNCIAS PyPI")
    log.info("=" * 55)

    G = load_graph(INPUT_FILE)
    metrics = compute_metrics(G)

    log.info("Gerando gráficos...")
    plot_degree_distribution(metrics)
    plot_scc_distribution(metrics)
    plot_top_packages(metrics)
    save_stats(metrics)

    print("\n[OK] Análise concluída! Arquivos gerados:")
    print(f"   📊 {FIGURES_DIR / 'degree_distribution.png'}")
    print(f"   📊 {FIGURES_DIR / 'scc_distribution.png'}")
    print(f"   📊 {FIGURES_DIR / 'top_packages.png'}")
    print(f"   📄 {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
