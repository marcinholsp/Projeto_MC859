"""
build_pypi_graph.py
===================
Constrói um grafo direcionado de dependências do PyPI a partir dos
top N pacotes mais baixados e salva em formato GraphML e GEXF.

Uso:
    pip install networkx requests tqdm
    python build_pypi_graph.py

Saída:
    pypi_dependency_graph.graphml
    pypi_dependency_graph.gexf
    build_log.txt
"""

import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import networkx as nx
import requests
from tqdm import tqdm

# ---------------------------------------------
#  CONFIGURAÇÕES — ajuste conforme necessário
# ---------------------------------------------
PROJECT_ROOT     = Path(__file__).resolve().parent.parent
DATA_DIR         = PROJECT_ROOT / "data"

TOP_N_PACKAGES   = 8000    # quantos pacotes do top downloads usar como semente prioritária
EXTRA_PACKAGES   = 40_000  # pacotes adicionais do PyPI Simple Index
MAX_NODES        = 100_000 # limite total de nós no grafo
MAX_WORKERS      = 20      # threads paralelas para requests HTTP
REQUEST_DELAY    = 0.05    # segundos entre requests dentro de cada worker
MAX_RETRIES      = 3       # tentativas por pacote em caso de erro
TIMEOUT          = 10      # timeout em segundos por request
OUTPUT_GRAPHML   = DATA_DIR / "pypi_dependency_graph.graphml"
OUTPUT_GEXF      = DATA_DIR / "pypi_dependency_graph.gexf"
LOG_FILE         = DATA_DIR / "build_log.txt"

# ---------------------------------------------
#  LOGGING
# ---------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ---------------------------------------------
#  SESSÕES THREAD-LOCAL
# ---------------------------------------------
_thread_local = threading.local()

def _get_session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({"User-Agent": "pypi-graph-builder/1.0 (academic research)"})
        _thread_local.session = s
    return _thread_local.session

# ---------------------------------------------
#  FUNÇÕES AUXILIARES
# ---------------------------------------------

def get_top_packages(n: int) -> list[str]:
    """
    Baixa a lista dos top N pacotes PyPI por downloads nos últimos 30 dias.
    Tenta duas URLs (GitHub Pages + raw GitHub) com retry automático.
    """
    urls = [
        "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
        "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages-30-days.min.json",
    ]
    for url in urls:
        for attempt in range(1, 4):
            try:
                log.info(f"Buscando top {n} pacotes em {url} (tentativa {attempt}/3)")
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                packages = [row["project"] for row in r.json()["rows"][:n]]
                log.info(f"{len(packages)} pacotes obtidos.")
                return packages
            except requests.exceptions.RequestException as e:
                log.warning(f"Falha ao buscar lista ({url}): {e}")
                time.sleep(3 * attempt)
    raise RuntimeError("Não foi possível obter a lista de top pacotes após todas as tentativas.")


def get_all_packages(n: int) -> list[str]:
    """
    Busca até N nomes de pacotes do PyPI Simple Index (JSON API).
    Retorna uma lista normalizada, excluindo pacotes já cobertos pelo top-N.
    """
    url = "https://pypi.org/simple/"
    headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
    for attempt in range(1, 4):
        try:
            log.info(f"Buscando PyPI Simple Index (tentativa {attempt}/3)...")
            r = requests.get(url, headers=headers, timeout=60)
            r.raise_for_status()
            projects = r.json().get("projects", [])
            names = [normalize_name(p["name"]) for p in projects[:n]]
            log.info(f"PyPI Simple Index: {len(projects):,} pacotes totais, usando {len(names):,}.")
            return names
        except requests.exceptions.RequestException as e:
            log.warning(f"Falha ao buscar Simple Index: {e}")
            time.sleep(3 * attempt)
    log.error("Não foi possível obter o Simple Index. Prosseguindo sem sementes extras.")
    return []


def normalize_name(name: str) -> str:
    """
    Normaliza o nome de um pacote PyPI (PEP 503).
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requires_dist(requires_dist: list[str]) -> list[str]:
    """
    Extrai dependências diretas de runtime a partir de requires_dist (PEP 508).
    Ignora dependências condicionais de extras (optional).
    """
    deps = []
    for spec in requires_dist:
        if 'extra ==' in spec or 'extra==' in spec:
            continue
        name = re.split(r"[\s\(\[;><=!~@]", spec)[0].strip()
        if name:
            deps.append(normalize_name(name))
    return deps


def fetch_package_info(package: str) -> dict | None:
    """
    Consulta a API JSON do PyPI para um pacote usando sessão thread-local.
    Retorna None em caso de falha permanente.
    """
    session = _get_session()
    url = f"https://pypi.org/pypi/{package}/json"
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            data = r.json()
            info = data.get("info", {})
            requires = info.get("requires_dist") or []
            time.sleep(REQUEST_DELAY)
            return {
                "name":      normalize_name(info.get("name", package)),
                "version":   info.get("version", ""),
                "deps":      parse_requires_dist(requires),
                "summary":   (info.get("summary") or "")[:200],
                "home_page": info.get("home_page") or "",
            }
        except requests.exceptions.Timeout:
            log.warning(f"Timeout em {package} (tentativa {attempt}/{MAX_RETRIES})")
        except requests.exceptions.RequestException as e:
            log.warning(f"Erro em {package} (tentativa {attempt}/{MAX_RETRIES}): {e}")
        time.sleep(REQUEST_DELAY * 2 * attempt)
    log.error(f"Falha permanente ao buscar {package}")
    return None


# ---------------------------------------------
#  CONSTRUÇÃO DO GRAFO (BFS por níveis + paralelo)
# ---------------------------------------------

def build_graph(seed_packages: list[str]) -> nx.DiGraph:
    """
    Constrói o grafo de dependências usando BFS por níveis com requests paralelos.

    A cada iteração, todos os pacotes do nível atual são buscados em paralelo
    com MAX_WORKERS threads. O grafo e os conjuntos seen/processed são atualizados
    apenas na thread principal, garantindo segurança sem locks adicionais.
    """
    G = nx.DiGraph()
    seen      = set()
    processed = set()

    # Inicializa com as sementes
    current_batch: list[tuple[str, bool]] = []
    for pkg in seed_packages:
        norm = normalize_name(pkg)
        if norm not in seen:
            seen.add(norm)
            current_batch.append((norm, True))

    pbar = tqdm(total=len(seen), unit="pkg", desc="Construindo grafo")

    while current_batch:
        # Filtra pacotes ainda não processados neste nível
        to_fetch = [(pkg, is_seed) for pkg, is_seed in current_batch
                    if pkg not in processed]
        for pkg, _ in to_fetch:
            processed.add(pkg)

        if not to_fetch:
            break

        next_batch: list[tuple[str, bool]] = []

        # Busca paralela: workers só fazem HTTP — grafo atualizado na thread principal
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(fetch_package_info, pkg): (pkg, is_seed)
                for pkg, is_seed in to_fetch
            }
            for future in as_completed(futures):
                pkg, is_seed = futures[future]
                info = future.result()
                pbar.update(1)

                if info is None:
                    continue

                name = info["name"]
                if not G.has_node(name):
                    G.add_node(name)
                G.nodes[name].update(
                    version=info["version"],
                    summary=info["summary"],
                    home_page=info["home_page"],
                    is_seed=is_seed,
                )

                for dep in info["deps"]:
                    G.add_edge(name, dep)
                    if dep not in seen and len(seen) < MAX_NODES:
                        seen.add(dep)
                        next_batch.append((dep, False))
                        pbar.total += 1
                        pbar.refresh()

        pbar.set_postfix(nodes=G.number_of_nodes(), edges=G.number_of_edges(),
                         fila=len(next_batch))
        current_batch = next_batch

    pbar.close()
    log.info(f"BFS concluído: {len(processed)} pacotes processados.")
    return G


# ---------------------------------------------
#  ANÁLISE BÁSICA DO GRAFO
# ---------------------------------------------

def analyze_graph(G: nx.DiGraph) -> dict:
    n  = G.number_of_nodes()
    m  = G.number_of_edges()
    avg_degree = (2 * m / n) if n > 0 else 0

    log.info("-" * 50)
    log.info("ANÁLISE DO GRAFO")
    log.info(f"  Vértices         : {n:,}")
    log.info(f"  Arestas          : {m:,}")
    log.info(f"  Grau médio       : {avg_degree:.2f}")

    sccs = list(nx.strongly_connected_components(G))
    n_sccs = len(sccs)
    sizes = sorted([len(c) for c in sccs], reverse=True)
    log.info(f"  CFCs totais      : {n_sccs:,}")
    log.info(f"  Maior CFC        : {sizes[0]:,} vértices")
    log.info(f"  CFCs singleton   : {sizes.count(1):,}")

    in_degrees = sorted(G.in_degree(), key=lambda x: x[1], reverse=True)
    log.info("  Top 10 mais dependidos (in-degree):")
    for pkg, deg in in_degrees[:10]:
        log.info(f"    {pkg:<35} in-degree={deg}")

    wccs = list(nx.weakly_connected_components(G))
    n_wccs = len(wccs)
    wcc_sizes = sorted([len(c) for c in wccs], reverse=True)
    log.info(f"  CCFs (fracas)    : {n_wccs:,}")
    log.info(f"  Maior CCF        : {wcc_sizes[0]:,} vértices")
    log.info("-" * 50)

    stats = {
        "n_vertices":       n,
        "n_arestas":        m,
        "grau_medio":       round(avg_degree, 2),
        "in_degree_medio":  round(m / n, 2) if n > 0 else 0,
        "out_degree_medio": round(m / n, 2) if n > 0 else 0,
        "in_degree_max":    in_degrees[0][1] if in_degrees else 0,
        "out_degree_max":   max(d for _, d in G.out_degree()),
        "n_sccs":           n_sccs,
        "maior_scc":        sizes[0] if sizes else 0,
        "n_singletons_scc": sizes.count(1),
        "n_wccs":           n_wccs,
        "maior_wcc":        wcc_sizes[0] if wcc_sizes else 0,
        "top_20_in_degree": in_degrees[:20],
    }

    stats_path = DATA_DIR / "stats.json"
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    log.info(f"Estatísticas salvas em {stats_path}")

    return stats


# ---------------------------------------------
#  SALVAMENTO
# ---------------------------------------------

def save_graph(G: nx.DiGraph):
    G_ml = G.copy()
    for _, attrs in G_ml.nodes(data=True):
        if "is_seed" in attrs:
            attrs["is_seed"] = str(attrs["is_seed"])

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    log.info(f"Salvando {OUTPUT_GRAPHML} ...")
    nx.write_graphml(G_ml, OUTPUT_GRAPHML)
    log.info(f"  [OK] {Path(OUTPUT_GRAPHML).stat().st_size / 1e6:.1f} MB")

    log.info(f"Salvando {OUTPUT_GEXF} ...")
    nx.write_gexf(G, OUTPUT_GEXF)
    log.info(f"  [OK] {Path(OUTPUT_GEXF).stat().st_size / 1e6:.1f} MB")


# ---------------------------------------------
#  MAIN
# ---------------------------------------------

def main():
    log.info("=" * 50)
    log.info("INICIANDO CONSTRUÇÃO DO GRAFO DE DEPENDÊNCIAS PyPI")
    log.info(f"  top_n={TOP_N_PACKAGES}  extra={EXTRA_PACKAGES}  max_nodes={MAX_NODES}  workers={MAX_WORKERS}")
    log.info("=" * 50)

    # Sementes prioritárias: top N por downloads
    top_seeds = get_top_packages(TOP_N_PACKAGES)
    top_set = set(top_seeds)

    # Sementes extras: PyPI Simple Index (exclui os já cobertos pelo top-N)
    extra_seeds = [p for p in get_all_packages(EXTRA_PACKAGES + TOP_N_PACKAGES)
                   if p not in top_set][:EXTRA_PACKAGES]
    log.info(f"Sementes: {len(top_seeds):,} (top downloads) + {len(extra_seeds):,} (simple index) = {len(top_seeds)+len(extra_seeds):,} total")

    seeds = top_seeds + extra_seeds
    G = build_graph(seeds)
    stats = analyze_graph(G)
    save_graph(G)

    log.info("CONCLUÍDO!")
    print("\n[OK] Grafo construído com sucesso!")
    print(f"   Vértices : {stats['n_vertices']:,}")
    print(f"   Arestas  : {stats['n_arestas']:,}")
    print(f"   Grau méd.: {stats['grau_medio']:.2f}")
    print(f"   CFCs     : {stats['n_sccs']:,}")


if __name__ == "__main__":
    main()
