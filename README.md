# RAG Threat Scenario Generator

Retrieval-augmented generation (RAG) system for cybersecurity threat scenario research. It loads MITRE Enterprise ATT&CK, MITRE ICS ATT&CK, and CISA ICS advisories, indexes them with contextual retrieval, and answers questions through a hybrid BM25 + vector + RRF pipeline with Qwen 2.5 via Ollama.

## Architecture (high level)

```text
Knowledge base (JSON/CSV)
  → Contextual chunking
  → Deterministic context generation (index time)
  → Embeddings (Ollama nomic-embed-text on contextual + original text)
  → ChromaDB vector index + BM25 over original text
  → Hybrid retrieval (RRF) → Context selection → Qwen 2.5 answer
```

## Prerequisites

| Requirement | Version / notes |
|-------------|-----------------|
| **Python** | 3.12 or newer |
| **Ollama** | Latest from [https://ollama.com](https://ollama.com) |
| **Git** | To clone the repository |
| **RAM** | 16 GB+ recommended for `qwen2.5:14b` locally |

### Knowledge base files (must be in project root)

These files are **not** always included in the repo due to size. Place them in the `ThreatGenerator/` folder:

- `enterprise-attack.json` — MITRE Enterprise ATT&CK
- `ics-attack.json` — MITRE ICS ATT&CK
- `CISA_ICS_ADV_Master.csv` — CISA ICS advisories

Download ATT&CK STIX/JSON from [MITRE ATT&CK](https://attack.mitre.org/). Use your own CISA advisory export for the CSV.

---

## 1. Install Ollama

### Windows

1. Download and install Ollama from [https://ollama.com/download](https://ollama.com/download).
2. After install, Ollama runs as a background service on **`http://localhost:11434`**.
3. Verify in PowerShell:

```powershell
ollama --version
```

### macOS / Linux

Install from [https://ollama.com/download](https://ollama.com/download), then verify with `ollama --version`.

---

## 2. Pull required Ollama models

This project uses **two** Ollama models:

| Model | Purpose | Default env override |
|-------|---------|----------------------|
| `qwen2.5:14b` | Answer generation (chat) | `RAG_OLLAMA_CHAT_MODEL` |
| `nomic-embed-text` | Vector embeddings | `RAG_OLLAMA_MODEL` |

Pull both:

```powershell
ollama pull qwen2.5:14b
ollama pull nomic-embed-text
```

Verify they are available:

```powershell
ollama list
```

Quick test:

```powershell
ollama run qwen2.5:14b "Say hello in one sentence."
```

---

## 3. Clone the repository

```powershell
git clone https://git.dataliz9r.net/sneha/Threat-Scenario-Description-Generator.git
cd Threat-Scenario-Description-Generator
```


## 4. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

On macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
```

---

## 5. Install Python dependencies

Install the package in editable mode:

```powershell
python -m pip install --upgrade pip
python -m pip install -e .
```

For development (tests):

```powershell
python -m pip install -e ".[dev]"
```

### Python packages installed

- `chromadb` — vector store
- `rank-bm25` — keyword retrieval
- `langchain-ollama` — Ollama chat + embeddings
- `langchain-core`, `pydantic`

---

## 6. First run (index + interactive CLI)

From the project root (where the JSON/CSV files live):

```powershell
rag-cli
```

**First launch** will:

1. Load and chunk the knowledge base
2. Generate deterministic contextual summaries (cached under `.rag/context_cache/`)
3. Embed chunks via Ollama and index into Chroma (`.rag/chroma/`)
4. Start an interactive prompt

Example session:

```text
Query: What is spearphishing?
Answer: ...
Sources
* Enterprise ATT&CK T1566.001
...
Query: [empty line to exit]
```

### First run can take a while

Indexing thousands of chunks calls Ollama for embeddings. Expect several minutes on first run. Later runs reuse the existing index.

---

## 7. CLI options

```powershell
rag-cli --help
```

| Flag | Description |
|------|-------------|
| `--reindex` | Force full Chroma rebuild |
| `--deterministic` | Use local deterministic embeddings (no Ollama for embeddings); useful for tests |
| `--debug-retrieval` | Print BM25, vector, and RRF rankings |
| `--root PATH` | Project root containing knowledge base files |
| `--top-k N` | Legacy retrieval pool size hint |

Examples:

```powershell
# Rebuild index after code or knowledge base changes
rag-cli --reindex

# Debug retrieval pipeline
$env:RAG_DEBUG_RETRIEVAL="1"
rag-cli --debug-retrieval
```

---

## 8. Environment variables

### Ollama connection

```powershell
$env:OLLAMA_BASE_URL="http://localhost:11434"
# or
$env:RAG_OLLAMA_BASE_URL="http://localhost:11434"
```

### Models

```powershell
$env:RAG_OLLAMA_CHAT_MODEL="qwen2.5:14b"
$env:RAG_OLLAMA_MODEL="nomic-embed-text"
```

### Storage paths

```powershell
$env:RAG_CHROMA_PATH="C:\path\to\chroma"
$env:RAG_CONTEXT_CACHE_PATH="C:\path\to\contexts.json"
```

### Indexing performance (low memory)

```powershell
$env:RAG_OLLAMA_EMBED_BATCH_SIZE="16"
$env:RAG_INDEX_BATCH_SIZE="32"
```

### Answer generation (deterministic defaults)

Defaults: `temperature=0`, `top_p=1`, `top_k=1`, `seed=42`. Override with:

- `RAG_OLLAMA_TEMPERATURE`
- `RAG_OLLAMA_TOP_P`
- `RAG_OLLAMA_TOP_K`
- `RAG_OLLAMA_SEED`
- `RAG_OLLAMA_NUM_PREDICT`

### Debug

```powershell
$env:RAG_DEBUG_RETRIEVAL="1"
$env:RAG_DEBUG_CONTEXT="1"
$env:DEBUG="true"
```

---

## 9. Run tests

```powershell
.\.venv\Scripts\Activate.ps1
pytest
```

Tests use deterministic embeddings where possible and do not require Ollama for most cases.

---

## 10. Project layout

```text
ThreatGenerator/
├── enterprise-attack.json      # MITRE Enterprise ATT&CK
├── ics-attack.json             # MITRE ICS ATT&CK
├── CISA_ICS_ADV_Master.csv     # CISA advisories
├── rag/
│   ├── cli.py                  # rag-cli entry point
│   ├── pipeline.py             # Indexing pipeline
│   ├── retrieval/              # BM25, vector, RRF, context selection
│   └── generation/             # Context builder, Qwen answer service
├── tests/
├── pyproject.toml
└── .rag/                       # Generated index + cache (gitignored)
    ├── chroma/
    └── context_cache/
```

---

## 11. Troubleshooting

### `Connection refused` to Ollama

- Ensure Ollama is running (system tray on Windows).
- Check: `curl http://localhost:11434/api/tags` or open that URL in a browser.

### `model not found`

```powershell
ollama pull qwen2.5:14b
ollama pull nomic-embed-text
```

### Embedding dimension mismatch

You switched between `--deterministic` and Ollama embeddings. Rebuild:

```powershell
rag-cli --reindex
```

Or delete `.rag/chroma/` and run again.

### Missing knowledge base files

Ensure `enterprise-attack.json`, `ics-attack.json`, and `CISA_ICS_ADV_Master.csv` are in the project root (or pass `--root`).

### Slow or out-of-memory during indexing

- Reduce batch sizes: `RAG_INDEX_BATCH_SIZE=16`, `RAG_OLLAMA_EMBED_BATCH_SIZE=8`
- Use a smaller chat model if needed: `RAG_OLLAMA_CHAT_MODEL=qwen2.5:7b`

---

## 12. Git remote

```text
https://git.dataliz9r.net/sneha/Threat-Scenario-Description-Generator.git
```

Typical workflow:

```powershell
git add .
git commit -m "Your message"
git pull origin main --rebase
git push origin main
```

---

## Thesis context

This project implements the retrieval subsystem for a Master's thesis on threat scenario generation for industrial control systems. Later stages (structured JSON input, DPO fine-tuning, deterministic threat scenario generation) build on this retrieval layer.
