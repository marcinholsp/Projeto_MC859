# pypi-vulnerability-graph

Análise de Resiliência e Propagação de Vulnerabilidades em Grafos de Dependências do Ecossistema Python  
**Projeto MC859 — UNICAMP, 2026**
### Aluno: Márcio Levi Sales Prado
### RA:183680

---

## Descrição

Este repositório contém os scripts de coleta, construção e análise do grafo de dependências do ecossistema PyPI, além das instâncias geradas.

O grafo é **direcionado**: uma aresta **A → B** indica que o pacote A depende de B. Os vértices representam pacotes Python e as arestas representam relações de dependência direta de runtime, extraídas da API pública do PyPI a partir dos 3.000 pacotes mais baixados nos últimos 30 dias.

---

## Instâncias (grafos)

| Arquivo | Formato | Vértices | Arestas | Download |
|---------|---------|----------|---------|----------|
| `pypi_dependency_graph.graphml` | GraphML | 3.359 | 9.662 | [graphml](data/pypi_dependency_graph.graphml) |
| `pypi_dependency_graph.gexf`    | GEXF    | 3.359 | 9.662 | [gexf](data/pypi_dependency_graph.gexf)    |

> Se os arquivos ultrapassarem 100 MB, estarão disponíveis via Git LFS ou no link alternativo indicado abaixo.

### Métricas principais

| Métrica | Valor |
|---------|-------|
| Vértices | 3.359 |
| Arestas | 9.662 |
| Grau médio | 5,75 |
| Componentes Fortemente Conexas (CFCs) | 3.351 |
| Maior CFC | 8 vértices |
| CFCs singleton | 3.349 |

---

## Estrutura do repositório

```
/
├── README.md
├── scripts/
│   ├── build_pypi_graph.py      ← coleta + construção do grafo
│   └── analyze_pypi_graph.py    ← métricas + visualizações
├── data/
│   ├── pypi_dependency_graph.graphml   ← instância principal
│   ├── pypi_dependency_graph.gexf      ← mesma instância, formato GEXF
│   ├── stats.json                      ← métricas em JSON
│   └── build_log.txt                   ← log da coleta
└── figures/
    ├── degree_distribution.png
    ├── scc_distribution.png
    └── top_packages.png
```

---

## Visualizações

### Distribuição de graus
![Distribuição de graus](assets/degree_distribution.png)

A distribuição segue uma lei de potência (*power-law*) em escala log-log, com expoentes −1,13 (in-degree) e −1,44 (grau total), característica de redes livres de escala (*scale-free*). Hubs como `typing-extensions` (in-degree 495) e `requests` (253) concentram a maior parte das dependências.

### Distribuição das CFCs
![Distribuição das CFCs](assets/scc_distribution.png)

99,94% das CFCs são singletons, confirmando que o ecossistema PyPI é essencialmente acíclico — dependências circulares são raras. Apenas 2 CFCs possuem mais de um vértice (tamanhos 2 e 8).

### Top 20 pacotes mais dependidos
![Top 20](assets/top_packages.png)

---

## Como reproduzir

```bash
# 1) Instalar dependências
pip install networkx requests tqdm matplotlib numpy

# 2) Construir o grafo (faz requests à API pública do PyPI — ~10 min)
python scripts/build_pypi_graph.py

# 3) Analisar e gerar figuras
python scripts/analyze_pypi_graph.py
```

Os scripts resolvem caminhos a partir da raiz do projeto, podendo ser executados diretamente de lá.

### Parâmetros configuráveis em `build_pypi_graph.py`

| Parâmetro | Padrão | Descrição |
|-----------|--------|-----------|
| `TOP_N_PACKAGES` | 3000 | Pacotes-semente do top downloads |
| `MAX_NODES` | 8000 | Limite total de nós no grafo |
| `REQUEST_DELAY` | 0.05s | Pausa entre requests (respeita rate-limit) |

---

## Fonte dos dados

| Dado | Fonte |
|------|-------|
| Dependências e metadados | [API JSON do PyPI](https://pypi.org/pypi/{package}/json) |
| Lista de pacotes mais baixados | [top-pypi-packages](https://hugovk.github.io/top-pypi-packages/) |
| Vulnerabilidades *(próxima etapa)* | [OSV API](https://osv.dev) + [GitHub Advisory Database](https://github.com/advisories) |

---

## Autor

Márcio Levi Sales Prado — MC859, UNICAMP, 2026
