"""Application settings.

Everything is env-driven; nothing secret is ever defaulted to a usable value in
production (see :meth:`Settings.validate_production`).
"""

from __future__ import annotations

import functools
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="forbid",
        case_sensitive=False,
    )

    # -- core -------------------------------------------------------------
    environment: Environment = "development"
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"
    project_name: str = "OpsPilot AI"

    secret_key: str = "insecure-dev-secret-key-do-not-use-in-production"
    encryption_key: str = ""
    access_token_ttl_minutes: int = 30
    refresh_token_ttl_days: int = 14
    jwt_algorithm: str = "HS256"

    # -- data -------------------------------------------------------------
    database_url: str = "postgresql+asyncpg://opspilot:opspilot@localhost:5432/opspilot"
    checkpoint_database_url: str = "postgresql://opspilot:opspilot@localhost:5432/opspilot"
    redis_url: str = "redis://localhost:6379/0"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False

    # -- llm --------------------------------------------------------------
    llm_provider: Literal["anthropic", "nvidia", "fake"] = "anthropic"
    anthropic_api_key: str = ""
    opspilot_model: str = "claude-sonnet-5"
    opspilot_model_fast: str = "claude-haiku-4-5-20251001"
    llm_timeout_seconds: int = 90
    llm_max_retries: int = 3
    llm_temperature: float = 0.0

    # -- nvidia nim -------------------------------------------------------
    # Defaults target the hosted catalogue; point nvidia_base_url at a NIM
    # container you run yourself (e.g. http://localhost:8000/v1) and the same
    # code path serves it.
    nvidia_api_key: str = ""
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"
    nvidia_model: str = "openai/gpt-oss-120b"
    nvidia_model_fast: str = "nvidia/nemotron-3.5-lightning-30b-a3b"
    # Every OpsPilot call is a schema request. Tool-capable NIM models serve
    # those through "function_calling"; models that expose guided decoding
    # instead want "json_schema".
    nvidia_structured_output_method: Literal["function_calling", "json_schema"] = "function_calling"
    # Per-million-token rates for the cost column. Zero by default because NIM
    # pricing depends on the deployment — a container you host costs nothing at
    # the API layer. Set these to your rates to make the column meaningful.
    nvidia_price_per_mtok_input: float = 0.0
    nvidia_price_per_mtok_output: float = 0.0

    # -- langsmith --------------------------------------------------------
    langchain_tracing_v2: bool = False
    langchain_project: str = "opspilot"
    langchain_api_key: str = ""
    langchain_endpoint: str = "https://api.smith.langchain.com"

    # -- web --------------------------------------------------------------
    cors_origins: str = "http://localhost:3000"

    # -- safety knobs -----------------------------------------------------
    remediation_disabled: bool = False
    auto_approve_low_risk: bool = True
    max_agent_iterations: int = 3
    investigation_timeout_seconds: int = 600
    tool_timeout_seconds: int = 45
    approval_ttl_minutes: int = 60

    # blast-radius ceilings enforced by the deterministic policy engine
    max_pods_restart: int = 20
    max_replica_delta: int = 10
    protected_namespaces: str = "kube-system,kube-public,istio-system,opspilot"

    webhook_signature_tolerance_seconds: int = 300

    @field_validator("cors_origins", "protected_namespaces", "nvidia_base_url")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def protected_namespace_set(self) -> frozenset[str]:
        return frozenset(n.strip() for n in self.protected_namespaces.split(",") if n.strip())

    @property
    def nvidia_is_hosted(self) -> bool:
        """True when we are calling NVIDIA's hosted catalogue rather than our own NIM."""
        return "api.nvidia.com" in self.nvidia_base_url

    @property
    def is_production(self) -> bool:
        return self.environment in ("staging", "production")

    @property
    def testing(self) -> bool:
        return self.environment == "test"

    def validate_production(self) -> None:
        """Fail fast at boot rather than silently running insecurely."""
        if not self.is_production:
            return
        problems: list[str] = []
        if "insecure-dev" in self.secret_key or len(self.secret_key) < 32:
            problems.append("SECRET_KEY must be a strong 32+ char value in production")
        if not self.encryption_key:
            problems.append("ENCRYPTION_KEY is required in production")
        for name, url in (
            ("DATABASE_URL", self.database_url),
            ("CHECKPOINT_DATABASE_URL", self.checkpoint_database_url),
            ("REDIS_URL", self.redis_url),
        ):
            lowered = url.lower()
            if "localhost" in lowered or "127.0.0.1" in lowered or "sqlite" in lowered:
                problems.append(f"{name} must not point at localhost/sqlite in production")
        if self.llm_provider == "anthropic" and not self.anthropic_api_key:
            problems.append("ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic")
        if self.llm_provider == "nvidia":
            if not self.nvidia_base_url:
                problems.append("NVIDIA_BASE_URL is required when LLM_PROVIDER=nvidia")
            # A self-hosted NIM container may legitimately have no key; the
            # hosted catalogue never does.
            elif self.nvidia_is_hosted and not self.nvidia_api_key:
                problems.append(
                    "NVIDIA_API_KEY is required when LLM_PROVIDER=nvidia "
                    "and NVIDIA_BASE_URL points at the hosted NIM catalogue"
                )
        if "*" in self.cors_origin_list:
            problems.append("CORS_ORIGINS must not be '*' in production")
        if problems:
            raise RuntimeError("Invalid production configuration:\n  - " + "\n  - ".join(problems))


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
