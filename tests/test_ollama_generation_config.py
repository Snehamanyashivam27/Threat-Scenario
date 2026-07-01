from __future__ import annotations

import pytest

from rag.generation.answer_service import OllamaAnswerService
from rag.generation.ollama_config import OllamaGenerationConfig, load_ollama_generation_config


def test_load_ollama_generation_config_defaults():
    config = load_ollama_generation_config()
    assert config.temperature == 0.0
    assert config.top_p == 1.0
    assert config.top_k == 1
    assert config.seed == 42
    assert config.repeat_penalty == 1.0
    assert config.tfs_z == 1.0
    assert config.mirostat == 0


def test_load_ollama_generation_config_reads_env(monkeypatch):
    monkeypatch.setenv("RAG_OLLAMA_TEMPERATURE", "0")
    monkeypatch.setenv("RAG_OLLAMA_TOP_P", "1")
    monkeypatch.setenv("RAG_OLLAMA_TOP_K", "1")
    monkeypatch.setenv("RAG_OLLAMA_SEED", "7")
    monkeypatch.setenv("RAG_OLLAMA_REPEAT_PENALTY", "1.05")
    monkeypatch.setenv("RAG_OLLAMA_NUM_PREDICT", "512")

    config = load_ollama_generation_config()
    assert config.seed == 7
    assert config.repeat_penalty == 1.05
    assert config.num_predict == 512


def test_ollama_answer_service_passes_deterministic_chat_settings(monkeypatch):
    captured: dict[str, object] = {}

    class FakeChatOllama:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def invoke(self, prompt: str):
            return type("Response", (), {"content": "Deterministic answer with T1190."})()

    monkeypatch.setattr("langchain_ollama.ChatOllama", FakeChatOllama)

    service = OllamaAnswerService(
        generation_config=OllamaGenerationConfig(
            temperature=0.0,
            top_p=1.0,
            top_k=1,
            seed=42,
            repeat_penalty=1.0,
            tfs_z=1.0,
            mirostat=0,
        )
    )
    answer = service.generate("What is T1190?", "Enterprise ATT&CK\nTechnique: Example (T1190)")

    assert answer == "Deterministic answer with T1190."
    assert captured["temperature"] == 0.0
    assert captured["top_p"] == 1.0
    assert captured["top_k"] == 1
    assert captured["seed"] == 42
    assert captured["repeat_penalty"] == 1.0
    assert captured["tfs_z"] == 1.0
    assert captured["mirostat"] == 0
