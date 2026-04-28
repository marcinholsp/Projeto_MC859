"""
fetch_vulnerabilities.py
========================
Consulta a OSV API (https://api.osv.dev) para cada pacote do grafo
e anota os nós com atributos de vulnerabilidade.

Saída:
    data/pypi_vulns.json                ← mapa {package: [vuln, ...]}
    data/pypi_dependency_graph_vuln.graphml  ← grafo anotado com CVEs

Uso:
    pip install networkx requests tqdm
    python fetch_vulnerabilities.py

Atributos adicionados aos nós:
    vuln_count   : número de vulnerabilidades conhecidas
    vuln_ids     : lista de IDs (CVE-XXXX-XXXX, GHSA-...) separados por '|'
    max_cvss     : maior CVSS score encontrado (0.0 se não disponível)
    vuln_summary : resumo da vulnerabilidade mais grave
"""

import json
import logging
import time
from pathlib import Path

import networkx as nx
import requests
from tqdm import tqdm

# ---------------------------------------------
#  CONFIGURAÇÕES
# ---------------------------------------------
PROJECT_ROOT   = Path(__file__).resolve().parent.parent
DATA_DIR       = PROJECT_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

INPUT_GRAPHML  = DATA_DIR / "pypi_dependency_graph.graphml"
OUTPUT_GRAPHML = DATA_DIR / "pypi_dependency_graph_vuln.graphml"
OUTPUT_JSON    = DATA_DIR / "pypi_vulns.json"

OSV_API_URL    = "https://api.osv.dev/v1/query"
REQUEST_DELAY  = 0.05   # segundos entre requests
MAX_RETRIES    = 3
TIMEOUT        = 15
BATCH_SIZE     = 100    # consultas por lote (a OSV suporta batch via /v1/querybatch)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(DATA_DIR / "vuln_fetch_log.txt", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)


# ---------------------------------------------
#  CONSULTA À OSV API (batch)
# ---------------------------------------------

def query_osv_batch(packages: list[str], session: requests.Session) -> dict[str, list]:
    """
    Consulta a OSV API em lotes usando /v1/querybatch.
    Retorna {package_name: [vuln_dict, ...]}
    """
    url = "https://api.osv.dev/v1/querybatch"
    queries = [
        {"package": {"name": pkg, "ecosystem": "PyPI"}}
        for pkg in packages
    ]
    payload = {"queries": queries}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.post(url, json=payload, timeout=TIMEOUT)
            r.raise_for_status()
            results = r.json().get("results", [])
            out = {}
            for pkg, result in zip(packages, results):
                out[pkg] = result.get("vulns", [])
            return out
        except requests.exceptions.RequestException as e:
            log.warning(f"Erro na OSV batch (tentativa {attempt}/{MAX_RETRIES}): {e}")
            time.sleep(2 * attempt)

    # fallback: retorna vazio para todos
    return {pkg: [] for pkg in packages}


def extract_cvss(vuln: dict) -> float:
    """
    Extrai o maior CVSS score numérico de uma vulnerabilidade OSV.

    A OSV API retorna o score como vetor (ex: "CVSS:3.1/AV:N/AC:L/..."),
    não como número. Usa a biblioteca cvss para calcular o base score.
    Fallback: mapa categorical (database_specific.severity).
    """
    from cvss import CVSS2, CVSS3, CVSS4
    SEVERITY_MAP = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5,
                    "MEDIUM": 5.0, "LOW": 2.5}

    best = 0.0
    for sev in vuln.get("severity", []):
        vector = sev.get("score", "")
        stype  = sev.get("type", "")
        try:
            if "CVSS:4" in vector or stype == "CVSS_V4":
                score = float(CVSS4(vector).base_score)
            elif "CVSS:3" in vector or stype in ("CVSS_V3", "CVSS_V31"):
                score = float(CVSS3(vector).base_score)
            elif "CVSS:2" in vector or stype == "CVSS_V2":
                score = float(CVSS2(vector).base_score)
            else:
                score = 0.0
            best = max(best, score)
        except Exception:
            pass

    # Fallback: severidade categórica da GitHub Advisory
    if best == 0.0:
        db_sev = vuln.get("database_specific", {}).get("severity", "")
        best = SEVERITY_MAP.get(db_sev.upper(), 0.0)

    return best


def extract_vuln_ids(vuln: dict) -> list[str]:
    """Retorna todos os IDs associados (CVE, GHSA, OSV, etc.)."""
    ids = [vuln.get("id", "")]
    for alias in vuln.get("aliases", []):
        ids.append(alias)
    return [i for i in ids if i]


# ---------------------------------------------
#  PIPELINE PRINCIPAL
# ---------------------------------------------

def fetch_all_vulnerabilities(G: nx.DiGraph) -> dict:
    """
    Para cada nó do grafo, consulta a OSV API e retorna o mapa completo
    {package: {"vuln_count": int, "vuln_ids": [...], "max_cvss": float, "vuln_summary": str}}
    """
    packages = list(G.nodes())
    total    = len(packages)
    log.info(f"Consultando OSV API para {total:,} pacotes em lotes de {BATCH_SIZE}...")

    vuln_map = {}
    session  = requests.Session()
    session.headers.update({"User-Agent": "pypi-vuln-graph/1.0 (academic research)"})

    batches = [packages[i:i+BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]

    with tqdm(total=total, unit="pkg", desc="Consultando OSV") as pbar:
        for batch in batches:
            results = query_osv_batch(batch, session)
            for pkg, vulns in results.items():
                if not vulns:
                    vuln_map[pkg] = {
                        "vuln_count":   0,
                        "vuln_ids":     [],
                        "max_cvss":     0.0,
                        "vuln_summary": "",
                    }
                else:
                    all_ids  = []
                    max_cvss = 0.0
                    summary  = ""
                    worst_vuln = None

                    for v in vulns:
                        ids   = extract_vuln_ids(v)
                        cvss  = extract_cvss(v)
                        all_ids.extend(ids)
                        if cvss > max_cvss:
                            max_cvss  = cvss
                            worst_vuln = v

                    if worst_vuln:
                        summary = (worst_vuln.get("summary") or "")[:200]

                    vuln_map[pkg] = {
                        "vuln_count":   len(vulns),
                        "vuln_ids":     list(set(all_ids)),
                        "max_cvss":     round(max_cvss, 1),
                        "vuln_summary": summary,
                    }
            pbar.update(len(batch))
            time.sleep(REQUEST_DELAY)

    session.close()

    total_vuln = sum(1 for v in vuln_map.values() if v["vuln_count"] > 0)
    log.info(f"OSV concluído: {total_vuln:,} pacotes com ao menos 1 vulnerabilidade.")
    return vuln_map


def annotate_graph(G: nx.DiGraph, vuln_map: dict) -> nx.DiGraph:
    """
    Adiciona atributos de vulnerabilidade a cada nó do grafo.
    """
    log.info("Anotando nós do grafo com dados de vulnerabilidade...")
    for node in G.nodes():
        info = vuln_map.get(node, {"vuln_count": 0, "vuln_ids": [], "max_cvss": 0.0, "vuln_summary": ""})
        G.nodes[node]["vuln_count"]   = info["vuln_count"]
        G.nodes[node]["vuln_ids"]     = "|".join(info["vuln_ids"])   # GraphML não suporta listas
        G.nodes[node]["max_cvss"]     = info["max_cvss"]
        G.nodes[node]["vuln_summary"] = info["vuln_summary"]
        # Converte bool para str (requisito do GraphML)
        if "is_seed" in G.nodes[node]:
            G.nodes[node]["is_seed"] = str(G.nodes[node]["is_seed"])
    return G


def print_summary(vuln_map: dict):
    """Exibe um resumo das vulnerabilidades encontradas."""
    total     = len(vuln_map)
    com_vuln  = sum(1 for v in vuln_map.values() if v["vuln_count"] > 0)
    criticos  = [(pkg, v) for pkg, v in vuln_map.items() if v["max_cvss"] >= 9.0]
    altos     = [(pkg, v) for pkg, v in vuln_map.items() if 7.0 <= v["max_cvss"] < 9.0]

    log.info("-" * 55)
    log.info("RESUMO DE VULNERABILIDADES")
    log.info(f"  Total de pacotes analisados : {total:,}")
    log.info(f"  Com ao menos 1 CVE          : {com_vuln:,} ({100*com_vuln/total:.1f}%)")
    log.info(f"  Críticos (CVSS ≥ 9.0)       : {len(criticos):,}")
    log.info(f"  Altos    (CVSS 7–9)          : {len(altos):,}")
    log.info("  Top 10 por CVSS:")
    top = sorted(vuln_map.items(), key=lambda x: x[1]["max_cvss"], reverse=True)[:10]
    for pkg, v in top:
        if v["max_cvss"] > 0:
            log.info(f"    {pkg:<35} CVSS={v['max_cvss']}  vulns={v['vuln_count']}")
    log.info("-" * 55)


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    log.info("=" * 55)
    log.info("COLETA DE VULNERABILIDADES — OSV API")
    log.info("=" * 55)

    # 1. Carrega grafo
    log.info(f"Carregando grafo: {INPUT_GRAPHML}")
    G = nx.read_graphml(INPUT_GRAPHML)
    log.info(f"  {G.number_of_nodes():,} nós | {G.number_of_edges():,} arestas")

    # 2. Consulta OSV
    vuln_map = fetch_all_vulnerabilities(G)

    # 3. Salva JSON bruto
    log.info(f"Salvando {OUTPUT_JSON} ...")
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(vuln_map, f, ensure_ascii=False, indent=2)
    log.info(f"  [OK] {Path(OUTPUT_JSON).stat().st_size / 1e6:.1f} MB")

    # 4. Anota grafo e salva GraphML
    G = annotate_graph(G, vuln_map)
    log.info(f"Salvando {OUTPUT_GRAPHML} ...")
    nx.write_graphml(G, OUTPUT_GRAPHML)
    log.info(f"  [OK] {Path(OUTPUT_GRAPHML).stat().st_size / 1e6:.1f} MB")

    # 5. Resumo
    print_summary(vuln_map)

    print("\n[OK] Concluido!")
    print(f"   JSON: {OUTPUT_JSON}")
    print(f"   GraphML: {OUTPUT_GRAPHML}")


if __name__ == "__main__":
    main()
