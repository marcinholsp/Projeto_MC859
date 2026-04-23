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
import time
from collections import deque
from pathlib import Path

import networkx as nx
import requests
from tqdm import tqdm

# ─────────────────────────────────────────────
#  CONFIGURAÇÕES — ajuste conforme necessário
# ─────────────────────────────────────────────
PROJECT_ROOT     = Path(__file__).resolve().parent.parent
DATA_DIR         = PROJECT_ROOT / "data"

TOP_N_PACKAGES   = 3000   # quantos pacotes do top downloads usar como semente
MAX_NODES        = 8000   # limite total de nós no grafo (evita explosão)
REQUEST_DELAY    = 0.05   # segundos entre requests (respeita rate-limit da API)
MAX_RETRIES      = 3      # tentativas por pacote em caso de erro
TIMEOUT          = 10     # timeout em segundos por request
OUTPUT_GRAPHML   = DATA_DIR / "pypi_dependency_graph.graphml"
OUTPUT_GEXF      = DATA_DIR / "pypi_dependency_graph.gexf"
LOG_FILE         = DATA_DIR / "build_log.txt"

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  FUNÇÕES AUXILIARES
# ─────────────────────────────────────────────

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
                r = requests.get(url, timeout=30)   # timeout maior para esta chamada
                r.raise_for_status()
                packages = [row["project"] for row in r.json()["rows"][:n]]
                log.info(f"{len(packages)} pacotes obtidos.")
                return packages
            except requests.exceptions.RequestException as e:
                log.warning(f"Falha ao buscar lista ({url}): {e}")
                time.sleep(3 * attempt)
    raise RuntimeError("Não foi possível obter a lista de top pacotes após todas as tentativas.")


def normalize_name(name: str) -> str:
    """
    Normaliza o nome de um pacote PyPI:
    - lowercase
    - substitui '_' e '.' por '-'
    Segue PEP 503 (canonical form).
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requires_dist(requires_dist: list[str]) -> list[str]:
    """
    Extrai os nomes das dependências diretas de runtime a partir de
    requires_dist (lista de strings no formato PEP 508).

    Exemplos de entrada:
        'requests (>=2.28)'
        'numpy>=1.21; python_version >= "3.8"'
        'pytest; extra == "dev"'   ← extras são ignorados

    Retorna apenas dependências obrigatórias (sem marcadores de extra).
    """
    deps = []
    for spec in requires_dist:
        # Ignora dependências condicionais de extras (optional)
        if 'extra ==' in spec or 'extra==' in spec:
            continue
        # Extrai o nome: tudo antes de espaço, '(', '[', ';', '>'
        name = re.split(r"[\s\(\[;><=!~@]", spec)[0].strip()
        if name:
            deps.append(normalize_name(name))
    return deps


def fetch_package_info(package: str, session: requests.Session) -> dict | None:
    """
    Consulta a API JSON do PyPI para um pacote e retorna um dicionário com:
        - name        : nome normalizado
        - version     : versão mais recente
        - deps        : lista de dependências diretas de runtime
        - downloads   : estimativa de downloads (não fornecida pela API JSON;
                        campo reservado para integração futura via BigQuery)
        - summary     : descrição curta
        - home_page   : URL do projeto
    Retorna None em caso de falha permanente.
    """
    url = f"https://pypi.org/pypi/{package}/json"
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 404:
                log.warning(f"Pacote não encontrado: {package}")
                return None
            r.raise_for_status()
            data = r.json()
            info = data.get("info", {})
            requires = info.get("requires_dist") or []
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
        time.sleep(REQUEST_DELAY * 2 * attempt)   # back-off exponencial
    log.error(f"Falha permanente ao buscar {package}")
    return None


# ─────────────────────────────────────────────
#  CONSTRUÇÃO DO GRAFO (BFS a partir do top-N)
# ─────────────────────────────────────────────

def build_graph(seed_packages: list[str]) -> nx.DiGraph:
    """
    Constrói o grafo de dependências usando BFS a partir dos pacotes-semente.

    Estratégia (dois conjuntos distintos):
        - seen      : pacotes já adicionados como nó (podem ser folhas temporárias)
        - processed : pacotes cujas dependências já foram buscadas e adicionadas

    O limite MAX_NODES controla apenas a adição de nós NOVOS descobertos como
    dependência. Pacotes já em 'seen' (adicionados como nó por serem dependência
    de outro) sempre terão suas próprias dependências buscadas, garantindo que
    nenhum nó fique como folha artificial sem ter sido processado.

    Atributos dos nós:
        - version   : versão mais recente
        - summary   : descrição curta
        - home_page : URL do projeto
        - is_seed   : True se o pacote estava na lista top-N original
    """
    G = nx.DiGraph()
    seen      = set()   # já existe como nó no grafo (ou vai existir)
    processed = set()   # já teve suas dependências buscadas
    queue     = deque()

    # Enfileira sementes
    for pkg in seed_packages:
        norm = normalize_name(pkg)
        if norm not in seen:
            seen.add(norm)
            queue.append((norm, True))   # (nome, is_seed)

    session = requests.Session()
    session.headers.update({"User-Agent": "pypi-graph-builder/1.0 (academic research)"})

    pbar = tqdm(total=len(seen), unit="pkg", desc="Construindo grafo")

    while queue:
        package, is_seed = queue.popleft()

        # Nunca processa o mesmo pacote duas vezes
        if package in processed:
            pbar.update(1)
            continue
        processed.add(package)

        info = fetch_package_info(package, session)
        time.sleep(REQUEST_DELAY)

        if info is None:
            pbar.update(1)
            continue

        name = info["name"]

        # Garante que o nó existe com atributos completos
        if not G.has_node(name):
            G.add_node(name)
        G.nodes[name].update(
            version=info["version"],
            summary=info["summary"],
            home_page=info["home_page"],
            is_seed=is_seed,
        )

        # Adiciona arestas para cada dependência direta
        for dep in info["deps"]:
            # Sempre adiciona a aresta (o nó dep pode ser folha por ora)
            G.add_edge(name, dep)

            # Enfileira dep para processamento se:
            #   1. ainda não foi processado/enfileirado, E
            #   2. não ultrapassamos MAX_NODES (só restringe nós NOVOS)
            if dep not in seen:
                if len(seen) < MAX_NODES:
                    seen.add(dep)
                    queue.append((dep, False))
                    pbar.total += 1
                    pbar.refresh()
                # Se MAX_NODES atingido: aresta existe, dep vira folha — aceitável.
                # O importante é que todo nó em 'seen' seja processado.
            # Se dep já está em 'seen' mas não em 'processed', já está na fila.

        pbar.update(1)
        pbar.set_postfix(nodes=G.number_of_nodes(), edges=G.number_of_edges(),
                         queue=len(queue))

    pbar.close()
    session.close()

    log.info(f"BFS concluído: {len(processed)} pacotes processados, "
             f"{len(seen) - len(processed)} na fila não processados.")
    return G


# ─────────────────────────────────────────────
#  ANÁLISE BÁSICA DO GRAFO
# ─────────────────────────────────────────────

def analyze_graph(G: nx.DiGraph) -> dict:
    """
    Calcula métricas básicas para exibição e logging.
    """
    n  = G.number_of_nodes()
    m  = G.number_of_edges()
    avg_degree = (2 * m / n) if n > 0 else 0  # grau médio (não-direcionado)

    log.info("─" * 50)
    log.info("ANÁLISE DO GRAFO")
    log.info(f"  Vértices         : {n:,}")
    log.info(f"  Arestas          : {m:,}")
    log.info(f"  Grau médio       : {avg_degree:.2f}")

    # Componentes fortemente conexas
    sccs = list(nx.strongly_connected_components(G))
    n_sccs = len(sccs)
    sizes = sorted([len(c) for c in sccs], reverse=True)
    log.info(f"  CFCs totais      : {n_sccs:,}")
    log.info(f"  Maior CFC        : {sizes[0]:,} vértices")
    log.info(f"  CFCs singleton   : {sizes.count(1):,}")

    # Top 10 por grau de entrada (in-degree = mais dependido)
    in_degrees = sorted(G.in_degree(), key=lambda x: x[1], reverse=True)
    log.info("  Top 10 mais dependidos (in-degree):")
    for pkg, deg in in_degrees[:10]:
        log.info(f"    {pkg:<35} in-degree={deg}")

    log.info("─" * 50)

    return {
        "n_vertices": n,
        "n_arestas": m,
        "grau_medio": avg_degree,
        "n_sccs": n_sccs,
        "tamanho_maior_scc": sizes[0] if sizes else 0,
        "n_singletons": sizes.count(1),
    }


# ─────────────────────────────────────────────
#  SALVAMENTO
# ─────────────────────────────────────────────

def save_graph(G: nx.DiGraph):
    """
    Salva o grafo em GraphML e GEXF.

    Nota: NetworkX exige que atributos booleanos sejam convertidos para
    string no GraphML; o GEXF suporta bool nativamente.
    """
    # GraphML: converte bool → string para evitar erro de serialização
    G_ml = G.copy()
    for _, attrs in G_ml.nodes(data=True):
        if "is_seed" in attrs:
            attrs["is_seed"] = str(attrs["is_seed"])

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    log.info(f"Salvando {OUTPUT_GRAPHML} ...")
    nx.write_graphml(G_ml, OUTPUT_GRAPHML)
    log.info(f"  ✓ {Path(OUTPUT_GRAPHML).stat().st_size / 1e6:.1f} MB")

    log.info(f"Salvando {OUTPUT_GEXF} ...")
    nx.write_gexf(G, OUTPUT_GEXF)
    log.info(f"  ✓ {Path(OUTPUT_GEXF).stat().st_size / 1e6:.1f} MB")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    log.info("=" * 50)
    log.info("INICIANDO CONSTRUÇÃO DO GRAFO DE DEPENDÊNCIAS PyPI")
    log.info("=" * 50)

    # 1. Obtém sementes
    seeds = get_top_packages(TOP_N_PACKAGES)

    # 2. Constrói grafo via BFS
    G = build_graph(seeds)

    # 3. Análise
    stats = analyze_graph(G)

    # 4. Salva
    save_graph(G)

    # 5. Resumo final
    log.info("CONCLUÍDO!")
    log.info(f"  Grafo salvo em: {OUTPUT_GRAPHML} e {OUTPUT_GEXF}")
    log.info(f"  Log completo : {LOG_FILE}")
    print("\n✅ Grafo construído com sucesso!")
    print(f"   Vértices : {stats['n_vertices']:,}")
    print(f"   Arestas  : {stats['n_arestas']:,}")
    print(f"   Grau méd.: {stats['grau_medio']:.2f}")
    print(f"   CFCs     : {stats['n_sccs']:,}")


if __name__ == "__main__":
    main()
