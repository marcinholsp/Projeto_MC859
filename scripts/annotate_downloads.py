"""
annotate_downloads.py
=====================
Anota cada nó do grafo de dependências com o número de downloads mensais
proveniente do top-pypi-packages (hugovk.github.io).

Pacotes fora da lista recebem downloads=0.

Salva:
    data/pypi_dependency_graph.graphml   (atualizado in-place)
    data/pypi_dependency_graph.gexf      (atualizado in-place)
    data/pypi_dependency_graph_vuln.graphml (se existir)
    data/downloads_map.json              (mapa nome→downloads para inspeção)

Uso:
    python scripts/annotate_downloads.py
"""

import json
import logging
import re
import time
from pathlib import Path

import networkx as nx
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR     = PROJECT_ROOT / "data"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

TOP_PACKAGES_URLS = [
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages-30-days.min.json",
]


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_downloads() -> dict[str, int]:
    """Retorna mapa {nome_normalizado: download_count} para TODOS os pacotes da lista."""
    for url in TOP_PACKAGES_URLS:
        for attempt in range(1, 4):
            try:
                log.info(f"Buscando top-pypi-packages ({url}) tentativa {attempt}/3")
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                rows = r.json()["rows"]
                dl_map = {normalize_name(row["project"]): int(row["download_count"])
                          for row in rows}
                log.info(f"  {len(dl_map):,} pacotes com dados de download")
                return dl_map
            except Exception as e:
                log.warning(f"Falha: {e}")
                time.sleep(3 * attempt)
    raise RuntimeError("Não foi possível obter dados de download.")


def annotate_graph(G: nx.DiGraph, dl_map: dict[str, int]) -> nx.DiGraph:
    """Adiciona atributo 'downloads' a cada nó."""
    hit, miss = 0, 0
    for node in G.nodes():
        key = normalize_name(node)
        d = dl_map.get(key, 0)
        G.nodes[node]["downloads"] = d
        if d > 0:
            hit += 1
        else:
            miss += 1
    log.info(f"  Nós com downloads > 0: {hit:,} | sem dados (downloads=0): {miss:,}")
    return G


def save_graph(G: nx.DiGraph, graphml_path: Path, gexf_path: Path | None = None):
    G_ml = G.copy()
    for _, attrs in G_ml.nodes(data=True):
        if "is_seed" in attrs:
            attrs["is_seed"] = str(attrs["is_seed"])

    log.info(f"Salvando {graphml_path} ...")
    nx.write_graphml(G_ml, graphml_path)
    log.info(f"  [OK] {graphml_path.stat().st_size / 1e6:.1f} MB")

    if gexf_path:
        log.info(f"Salvando {gexf_path} ...")
        nx.write_gexf(G, gexf_path)
        log.info(f"  [OK] {gexf_path.stat().st_size / 1e6:.1f} MB")


def main():
    log.info("=" * 55)
    log.info("ANOTANDO GRAFO COM DADOS DE DOWNLOAD")
    log.info("=" * 55)

    dl_map = fetch_downloads()

    # Salva mapa para inspeção
    dl_out = DATA_DIR / "downloads_map.json"
    with open(dl_out, "w", encoding="utf-8") as f:
        json.dump(dl_map, f, ensure_ascii=False, indent=2)
    log.info(f"Mapa de downloads salvo em {dl_out}")

    # Grafo principal
    graphml = DATA_DIR / "pypi_dependency_graph.graphml"
    gexf    = DATA_DIR / "pypi_dependency_graph.gexf"

    log.info(f"Carregando {graphml} ...")
    G = nx.read_graphml(graphml)
    log.info(f"  {G.number_of_nodes():,} nós | {G.number_of_edges():,} arestas")

    G = annotate_graph(G, dl_map)
    save_graph(G, graphml, gexf)

    # Grafo com vulnerabilidades (se existir)
    vuln_graphml = DATA_DIR / "pypi_dependency_graph_vuln.graphml"
    if vuln_graphml.exists():
        log.info(f"Carregando {vuln_graphml} ...")
        G_vuln = nx.read_graphml(vuln_graphml)
        G_vuln = annotate_graph(G_vuln, dl_map)
        save_graph(G_vuln, vuln_graphml)

    print("\n[OK] Downloads anotados nos grafos.")
    top5 = sorted(
        [(n, G.nodes[n]["downloads"]) for n in G.nodes()],
        key=lambda x: x[1], reverse=True
    )[:5]
    print("   Top 5 por downloads:")
    for name, d in top5:
        print(f"     {name:<35} {d:>15,}")


if __name__ == "__main__":
    main()
