from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    database_url: str = "postgresql+asyncpg://dpdpa:dpdpa@localhost:5432/dpdpa_reviewer"

    # Which provider writes the explanations. Embeddings always go to Gemini,
    # because DeepSeek publishes no embedding endpoint.
    ai_provider: str = "deepseek"

    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-flash"

    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    # gemini-embedding-001 emits 3072 dimensions by default. It is trained with
    # Matryoshka representation learning, so truncating to 768 keeps the useful
    # signal and lets the corpus table stay at vector(768).
    gemini_embedding_model: str = "gemini-embedding-001"
    gemini_embedding_dim: int = 768
    gemini_temperature: float = 0.1
    # Thinking models bill internal reasoning against this cap, and the
    # reasoning for a long compliance prompt routinely runs past a thousand
    # tokens before any JSON is emitted. 4096 truncated real explanations.
    gemini_max_output_tokens: int = 12288
    # A scan fires one generation per non-compliant rule back to back, which is
    # enough to trip a free-tier per-minute quota partway through and leave the
    # rest of the findings unexplained.
    gemini_max_retries: int = 4
    gemini_max_retry_wait: float = 65.0

    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    cors_origins: str = "http://localhost:5173"
    log_level: str = "INFO"

    # Lets the scanner reach localhost and private addresses. Required to
    # self-check an application running on your own machine, which is the
    # product's main use. A hosted instance must leave this off, or the
    # scan endpoint becomes an SSRF proxy into its own network.
    allow_private_scan_targets: bool = False

    max_crawl_pages: int = 10
    crawl_timeout_seconds: int = 30
    max_upload_size_mb: int = 50
    max_files_per_scan: int = 5000
    scan_workspace_dir: str = "./workspace"

    rag_top_k: int = 5
    rag_min_similarity: float = 0.35
    guardrail_quote_threshold: float = 0.85

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def generation_enabled(self) -> bool:
        if self.ai_provider == "deepseek":
            return bool(self.deepseek_api_key)
        return bool(self.gemini_api_key)

    @property
    def embedding_enabled(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def ai_enabled(self) -> bool:
        """Retrieval needs embeddings and explanation needs generation.

        Both must be present for a finding to carry a grounded citation, so the
        health check and the scan pipeline treat this as one switch.
        """
        return self.generation_enabled and self.embedding_enabled


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
