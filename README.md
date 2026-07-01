# RAG Threat Scenario Generator

This project implements the retrieval layer of my Threat Scenario Generator that generates threat scenario descriptions for industrial control systems.

It currently covers:

- loading CISA ICS advisories from `CISA_ICS_ADV_Master.csv`
- loading MITRE Enterprise ATT&CK from `enterprise-attack.json`
- loading MITRE ICS ATT&CK from `ics-attack.json`
- contextual chunking without fixed-size token splitting
- deterministic contextual summaries generated once at index time
- embeddings through Ollama's `nomic-embed-text` over `contextual_text + original_text`
- ChromaDB-backed vector storage with a persistent collection by default in the demo/runtime
- BM25 retrieval over original chunk text only
- hybrid retrieval with Reciprocal Rank Fusion
- a small demo script for top-k retrieval

## Indexing Pipeline

```text
Document
  -> Contextual Chunking
  -> Generate Context for each Chunk (index time only)
  -> Embed contextual_text + original_text
  -> ChromaDB
```

Contextual summaries are template-generated from document metadata and cached permanently in `.rag/context_cache/contexts.json` (override with `RAG_CONTEXT_CACHE_PATH`). They improve vector retrieval but are not sent to the answer-generation LLM, which uses the original ATT&CK/advisory text as the source of truth.

After upgrading to contextual RAG, rebuild the vector index. The default Chroma collection name is `rag_chunks_contextual`. Delete `.rag/chroma` or set `RAG_CHROMA_PATH` to a fresh directory before re-indexing.

## Install

```bash
python -m pip install -e .
```

## Run tests

```bash
pytest
```

## Demo

```bash
python -m rag.demo
```

Set `OLLAMA_BASE_URL` or `RAG_OLLAMA_BASE_URL` if Ollama is not on `localhost:11434`.
Set `RAG_CHROMA_PATH` to override the persistent Chroma directory.
Set `RAG_CONTEXT_CACHE_PATH` to override the contextual summary cache file.
Set `RAG_OLLAMA_EMBED_BATCH_SIZE` (default `16`) and `RAG_INDEX_BATCH_SIZE` (default `32`) to tune Ollama indexing batch sizes on memory-constrained machines.
Use `rag-cli --reindex` to force a full Chroma rebuild; otherwise an existing index is reused.

Ollama answer generation uses deterministic defaults: `temperature=0`, `top_p=1`, `top_k=1`, `seed=42`, `repeat_penalty=1.0`, `tfs_z=1.0`, `mirostat=0`. Override with `RAG_OLLAMA_TEMPERATURE`, `RAG_OLLAMA_TOP_P`, `RAG_OLLAMA_TOP_K`, `RAG_OLLAMA_SEED`, `RAG_OLLAMA_REPEAT_PENALTY`, `RAG_OLLAMA_TFS_Z`, `RAG_OLLAMA_MIROSTAT`, and optional `RAG_OLLAMA_NUM_PREDICT`.
