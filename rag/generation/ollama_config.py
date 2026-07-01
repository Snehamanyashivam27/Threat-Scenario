from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OllamaGenerationConfig:
    temperature: float = 0.0
    top_p: float = 1.0
    top_k: int = 1
    seed: int = 42
    repeat_penalty: float = 1.0
    tfs_z: float = 1.0
    mirostat: int = 0
    num_predict: int | None = None

    def to_chat_kwargs(self) -> dict[str, float | int]:
        kwargs: dict[str, float | int] = {
            "temperature": self.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "seed": self.seed,
            "repeat_penalty": self.repeat_penalty,
            "tfs_z": self.tfs_z,
            "mirostat": self.mirostat,
        }
        if self.num_predict is not None:
            kwargs["num_predict"] = self.num_predict
        return kwargs


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return float(value)


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


def load_ollama_generation_config() -> OllamaGenerationConfig:
    num_predict_raw = os.getenv("RAG_OLLAMA_NUM_PREDICT")
    num_predict = int(num_predict_raw) if num_predict_raw not in (None, "") else None
    return OllamaGenerationConfig(
        temperature=_env_float("RAG_OLLAMA_TEMPERATURE", 0.0),
        top_p=_env_float("RAG_OLLAMA_TOP_P", 1.0),
        top_k=_env_int("RAG_OLLAMA_TOP_K", 1),
        seed=_env_int("RAG_OLLAMA_SEED", 42),
        repeat_penalty=_env_float("RAG_OLLAMA_REPEAT_PENALTY", 1.0),
        tfs_z=_env_float("RAG_OLLAMA_TFS_Z", 1.0),
        mirostat=_env_int("RAG_OLLAMA_MIROSTAT", 0),
        num_predict=num_predict,
    )
