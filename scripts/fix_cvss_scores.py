"""
fix_cvss_scores.py
==================
O endpoint /v1/querybatch da OSV API retorna dados de vulnerabilidade
sem o campo 'severity' (apenas IDs). Este script re-consulta o endpoint
/v1/query (individual) somente para os pacotes com vuln_count > 0 e
extrai os CVSS scores numéricos usando a biblioteca cvss.

Atualiza:
    data/pypi_vulns.json
    data/pypi_dependency_graph_vuln.graphml

Uso:
    python scripts/fix_cvss_scores.py
"""

import json
import logging
import time
from pathlib import Path

import networkx as nx
import requests
from cvss import CVSS2, CVSS3, CVSS4
from tqdm import tqdm

PROJECT_ROOT   = Path(__file__).resolve().parent.parent
DATA_DIR       = PROJECT_ROOT / "data"
VULN_JSON      = DATA_DIR / "pypi_vulns.json"
VULN_GRAPHML   = DATA_DIR / "pypi_dependency_graph_vuln.graphml"
REQUEST_DELAY  = 0.05
MAX_RETRIES    = 3
TIMEOUT        = 15
SEVERITY_MAP   = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5,
                  "MEDIUM": 5.0, "LOW": 2.5}

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def extract_cvss(vuln: dict) -> float:
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
    if best == 0.0:
        db_sev = vuln.get("database_specific", {}).get("severity", "")
        best = SEVERITY_MAP.get(db_sev.upper(), 0.0)
    return best


def query_single(pkg: str, session: requests.Session) -> list[dict]:
    """Consulta /v1/query para um único pacote — retorna lista de vulns com severity."""
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": pkg, "ecosystem": "PyPI"}}
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.post(url, json=payload, timeout=TIMEOUT)
            r.raise_for_status()
            return r.json().get("vulns", [])
        except requests.exceptions.RequestException as e:
            log.warning(f"{pkg}: erro OSV (tentativa {attempt}): {e}")
            time.sleep(2 * attempt)
    return []


def main():
    log.info("=" * 55)
    log.info("CORRIGINDO CVSS SCORES (endpoint individual)")
    log.info("=" * 55)

    with open(VULN_JSON, encoding="utf-8") as f:
        vuln_map = json.load(f)

    # Apenas pacotes que têm ao menos 1 vulnerabilidade
    targets = [pkg for pkg, v in vuln_map.items() if v.get("vuln_count", 0) > 0]
    log.info(f"Re-consultando {len(targets)} pacotes com vulnerabilidades...")

    session = requests.Session()
    session.headers.update({"User-Agent": "pypi-vuln-graph/1.0 (academic research)"})

    updated = 0
    with tqdm(targets, unit="pkg", desc="Buscando CVSS") as pbar:
        for pkg in pbar:
            vulns = query_single(pkg, session)
            time.sleep(REQUEST_DELAY)

            if not vulns:
                continue

            all_ids  = []
            max_cvss = 0.0
            summary  = ""
            worst_vuln = None

            for v in vulns:
                ids  = [v.get("id", "")] + v.get("aliases", [])
                all_ids.extend(i for i in ids if i)
                cvss = extract_cvss(v)
                if cvss > max_cvss:
                    max_cvss = cvss
                    worst_vuln = v

            if worst_vuln:
                summary = (worst_vuln.get("summary") or "")[:200]

            vuln_map[pkg]["max_cvss"]     = round(max_cvss, 1)
            vuln_map[pkg]["vuln_ids"]     = list(set(all_ids))
            vuln_map[pkg]["vuln_summary"] = summary
            if max_cvss > 0:
                updated += 1
            pbar.set_postfix(updated=updated, last_cvss=round(max_cvss, 1))

    session.close()

    # Salva JSON
    with open(VULN_JSON, "w", encoding="utf-8") as f:
        json.dump(vuln_map, f, ensure_ascii=False, indent=2)
    log.info(f"JSON atualizado: {VULN_JSON}")

    # Re-anota grafo
    log.info(f"Carregando {VULN_GRAPHML} ...")
    G = nx.read_graphml(VULN_GRAPHML)
    for node in G.nodes():
        info = vuln_map.get(node, {})
        ids  = info.get("vuln_ids", [])
        G.nodes[node]["vuln_count"]   = info.get("vuln_count", 0)
        G.nodes[node]["vuln_ids"]     = "|".join(ids) if isinstance(ids, list) else ids
        G.nodes[node]["max_cvss"]     = info.get("max_cvss", 0.0)
        G.nodes[node]["vuln_summary"] = info.get("vuln_summary", "")
    nx.write_graphml(G, VULN_GRAPHML)
    log.info(f"Grafo re-anotado: {VULN_GRAPHML}")

    # Resumo
    top = sorted(
        [(k, v) for k, v in vuln_map.items() if v.get("max_cvss", 0) > 0],
        key=lambda x: x[1]["max_cvss"], reverse=True
    )
    criticos = sum(1 for _, v in top if v["max_cvss"] >= 9.0)
    altos    = sum(1 for _, v in top if 7.0 <= v["max_cvss"] < 9.0)
    log.info(f"Pacotes com CVSS > 0  : {len(top)}")
    log.info(f"Críticos (CVSS ≥ 9.0) : {criticos}")
    log.info(f"Altos    (CVSS 7–9)   : {altos}")
    log.info("Top 10:")
    for pkg, v in top[:10]:
        log.info(f"  {pkg:<35} CVSS={v['max_cvss']}  vulns={v['vuln_count']}")

    print(f"\n[OK] {updated} pacotes com CVSS > 0 após correção.")


if __name__ == "__main__":
    main()
