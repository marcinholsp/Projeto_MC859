# pypi-vulnerability-graph

Análise de Resiliência e Propagação de Vulnerabilidades em Grafos de Dependências do Ecossistema Python  
**Projeto MC859 — UNICAMP, 2026**

---

## Descrição

Este repositório contém os scripts de coleta, construção e análise do grafo de dependências do ecossistema PyPI, além das instâncias geradas. O grafo é direcionado: uma aresta **A → B** indica que o pacote A depende de B.

---

## Estrutura

```
/
├── README.md
├── scripts/
│   ├── build_pypi_graph.py      ← coleta + construção do grafo
│   └── analyze_pypi_graph.py    ← métricas + visualizações
├── data/
│   ├── pypi_dependency_graph.graphml   ← instância principal
│   └── pypi_dependency_graph.gexf      ← mesma instância, formato GEXF
└── figures/
    ├── degree_distribution.png
    ├── scc_distribution.png
    └── top_packages.png
```

---

## Instâncias (grafos)

| Arquivo | Formato | Download |
|---------|---------|----------|
| `pypi_dependency_graph.graphml` | GraphML | [link](data/pypi_dependency_graph.graphml) |
| `pypi_dependency_graph.gexf`    | GEXF    | [link](data/pypi_dependency_graph.gexf)    |

> Se os arquivos ultrapassarem 100 MB, estarão disponíveis via Git LFS ou no link alternativo indicado abaixo.

---

## Como reproduzir

```bash
# 1) Instalar dependências
pip install networkx requests tqdm matplotlib numpy

# 2) Construir o grafo (faz requests à API pública do PyPI)
python scripts/build_pypi_graph.py

# 3) Analisar e gerar figuras
python scripts/analyze_pypi_graph.py
```

### Arquivos gerados

- `scripts/build_pypi_graph.py`
  - `data/pypi_dependency_graph.graphml`
  - `data/pypi_dependency_graph.gexf`
  - `data/build_log.txt`
- `scripts/analyze_pypi_graph.py`
  - `data/stats.json`
  - `figures/degree_distribution.png`
  - `figures/scc_distribution.png`
  - `figures/top_packages.png`

### Parâmetros configuráveis em `build_pypi_graph.py`

| Parâmetro | Padrão | Descrição |
|-----------|--------|-----------|
| `TOP_N_PACKAGES` | 3000 | Pacotes-semente do top downloads |
| `MAX_NODES` | 8000 | Limite total de nós no grafo |
| `REQUEST_DELAY` | 0.05s | Pausa entre requests (respeita rate-limit) |

### Caminhos relativos usados pelos scripts

Os scripts resolvem caminhos a partir da raiz do projeto (via `Path(__file__).resolve().parent.parent`), então você pode executá-los da raiz com:

```bash
python scripts/build_pypi_graph.py
python scripts/analyze_pypi_graph.py
```

---

## Fonte dos dados

- **Dependências e metadados:** [API JSON do PyPI](https://pypi.org/pypi/{package}/json)
- **Lista de pacotes mais baixados:** [top-pypi-packages](https://hugovk.github.io/top-pypi-packages/)
- **Vulnerabilidades (próxima etapa):** [OSV API](https://osv.dev) + [GitHub Advisory Database](https://github.com/advisories)

---

## Autor

Márcio Levi Sales Prado — MC859, UNICAMP, março de 2026