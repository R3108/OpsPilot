"""LLM access layer.

One narrow interface — :meth:`LLMClient.structured` — so that:

* every call is a *schema* request, never free text;
* retries, timeouts and token accounting live in one place;
* LangSmith metadata is attached uniformly;
* the whole platform can run with ``LLM_PROVIDER=fake`` against a deterministic
  heuristic engine, which is what CI, the test suite and the offline demo use.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from app.core.config import settings
from app.core.errors import IntegrationError
from app.core.logging import get_logger

log = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)

# Per-million-token prices used for the cost column in the run table. NIM rates
# are not listed here because they depend on the deployment; NvidiaLLM reads
# them from settings instead.
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-5": (15.0, 75.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
}
DEFAULT_PRICING = (3.0, 15.0)


@dataclass(slots=True)
class LLMUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    model: str = ""
    latency_ms: int = 0
    calls: int = 0

    def add(self, other: LLMUsage) -> None:
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.cost_usd += other.cost_usd
        self.latency_ms += other.latency_ms
        self.calls += other.calls
        self.model = other.model or self.model


@dataclass(slots=True)
class LLMResponse:
    value: Any
    usage: LLMUsage = field(default_factory=LLMUsage)


def estimate_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    rates: tuple[float, float] | None = None,
) -> float:
    prompt_rate, completion_rate = rates or MODEL_PRICING.get(model, DEFAULT_PRICING)
    return round(
        (prompt_tokens / 1_000_000) * prompt_rate
        + (completion_tokens / 1_000_000) * completion_rate,
        6,
    )


class LLMClient(abc.ABC):
    """Structured-output-only interface."""

    @abc.abstractmethod
    async def structured(
        self,
        *,
        schema: type[T],
        system: str,
        user: str,
        purpose: str,
        fast: bool = False,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[T, LLMUsage]:
        """Ask for one instance of ``schema``.

        ``user`` is the rendered prompt the real model sees. ``context`` is the
        same information in structured form; only the offline heuristic engine
        reads it, so the two providers never diverge on what they were told.
        """

    @property
    @abc.abstractmethod
    def model_name(self) -> str: ...


class _LangChainLLM(LLMClient):
    """Shared machinery for every LangChain-backed provider.

    Providers differ only in how the chat model is constructed and which model
    ids they answer to. The retry budget, the schema-repair prompt, usage
    accounting and the LangSmith metadata are identical, so they live here once
    and no provider can quietly drift from the others.
    """

    # Some providers need `with_structured_output` steered at a particular
    # mechanism; ``None`` means "take the binding's default".
    structured_output_method: str | None = None

    def __init__(self) -> None:
        self._cache: dict[str, Any] = {}

    @abc.abstractmethod
    def _build_chat(self, model: str) -> Any:
        """Construct the provider's chat model for ``model``."""

    @abc.abstractmethod
    def _model_id(self, *, fast: bool) -> str:
        """The model id this provider should use for a normal / fast call."""

    def _rates(self, model: str) -> tuple[float, float]:
        return MODEL_PRICING.get(model, DEFAULT_PRICING)

    @property
    def model_name(self) -> str:
        return self._model_id(fast=False)

    def _chat(self, *, fast: bool) -> Any:
        model = self._model_id(fast=fast)
        if model not in self._cache:
            self._cache[model] = self._build_chat(model)
        return self._cache[model]

    def _bind(self, schema: type[T], *, fast: bool) -> Any:
        kwargs: dict[str, Any] = {"include_raw": True}
        if self.structured_output_method:
            kwargs["method"] = self.structured_output_method
        return self._chat(fast=fast).with_structured_output(schema, **kwargs)

    async def structured(
        self,
        *,
        schema: type[T],
        system: str,
        user: str,
        purpose: str,
        fast: bool = False,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[T, LLMUsage]:
        from langchain_core.messages import HumanMessage, SystemMessage

        model_name = self._model_id(fast=fast)
        chat = self._bind(schema, fast=fast)

        config: dict[str, Any] = {
            "run_name": f"opspilot.{purpose}",
            "tags": ["opspilot", purpose],
            "metadata": {"purpose": purpose, **(metadata or {})},
        }
        messages = [SystemMessage(content=system), HumanMessage(content=user)]

        last_error: Exception | None = None
        for attempt in range(1, settings.llm_max_retries + 1):
            started = time.perf_counter()
            try:
                raw = await chat.ainvoke(messages, config=config)
            except Exception as exc:  # noqa: BLE001 - provider errors vary widely
                last_error = exc
                log.warning(
                    "llm.call_failed", purpose=purpose, attempt=attempt, error=str(exc)[:300]
                )
                continue

            latency_ms = int((time.perf_counter() - started) * 1000)
            parsed = raw.get("parsed") if isinstance(raw, dict) else raw
            if parsed is None:
                # `include_raw` reports no parse *and* no parsing_error when the
                # model answered in prose instead of calling the tool at all. That
                # is a different failure from bad field values, and echoing the
                # literal "None" back at the model is no guidance for the retry.
                detail = raw.get("parsing_error") if isinstance(raw, dict) else None
                if detail is None:
                    detail = "no structured output at all — the model did not call the tool"
                answered = raw.get("raw") if isinstance(raw, dict) else None
                last_error = ValueError(
                    f"model did not return valid {schema.__name__}: {str(detail)[:300]}"
                )
                log.warning(
                    "llm.schema_violation",
                    purpose=purpose,
                    attempt=attempt,
                    schema=schema.__name__,
                    detail=str(detail)[:300],
                    # Without a sample of what it *did* say, this is undebuggable.
                    answered=str(getattr(answered, "content", ""))[:300],
                )
                # Give the model the validation error so the retry can correct it.
                messages = [
                    SystemMessage(content=system),
                    HumanMessage(
                        content=(
                            f"{user}\n\nYour previous response did not match the required "
                            f"schema ({last_error}). Return valid data for "
                            f"{schema.__name__} only."
                        )
                    ),
                ]
                continue

            usage = _usage_from_response(raw, model_name, latency_ms, self._rates(model_name))
            log.info(
                "llm.call",
                purpose=purpose,
                model=model_name,
                attempt=attempt,
                prompt_tokens=usage.prompt_tokens,
                completion_tokens=usage.completion_tokens,
                ms=latency_ms,
            )
            return parsed, usage

        raise IntegrationError(
            f"LLM call '{purpose}' failed after {settings.llm_max_retries} attempts: {last_error}",
            details={"purpose": purpose, "schema": schema.__name__},
        )


def _usage_from_response(
    raw: Any, model: str, latency_ms: int, rates: tuple[float, float] | None = None
) -> LLMUsage:
    message = raw.get("raw") if isinstance(raw, dict) else None
    meta = getattr(message, "usage_metadata", None) or {}
    prompt_tokens = int(meta.get("input_tokens", 0))
    completion_tokens = int(meta.get("output_tokens", 0))
    return LLMUsage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost_usd=estimate_cost(model, prompt_tokens, completion_tokens, rates),
        model=model,
        latency_ms=latency_ms,
        calls=1,
    )


class AnthropicLLM(_LangChainLLM):
    def _model_id(self, *, fast: bool) -> str:
        return settings.opspilot_model_fast if fast else settings.opspilot_model

    def _build_chat(self, model: str) -> Any:
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as exc:  # pragma: no cover
            raise IntegrationError(
                "langchain-anthropic is not installed; set LLM_PROVIDER=fake to run offline"
            ) from exc

        return ChatAnthropic(
            model=model,
            api_key=settings.anthropic_api_key or None,
            temperature=settings.llm_temperature,
            timeout=settings.llm_timeout_seconds,
            max_retries=0,  # we own the retry loop so we can log each attempt
            max_tokens=8192,
        )


class NvidiaLLM(_LangChainLLM):
    """NVIDIA NIM, reached over its OpenAI-compatible API.

    The same code path serves the hosted catalogue at ``integrate.api.nvidia.com``
    and a NIM container you run yourself — only ``NVIDIA_BASE_URL`` changes.
    Structured output goes through tool calling by default, which is what the
    tool-capable NIM models support; ``NVIDIA_STRUCTURED_OUTPUT_METHOD`` switches
    to guided JSON decoding for models that offer that instead.
    """

    @property
    def structured_output_method(self) -> str:  # type: ignore[override]
        return settings.nvidia_structured_output_method

    def _model_id(self, *, fast: bool) -> str:
        return settings.nvidia_model_fast if fast else settings.nvidia_model

    def _rates(self, model: str) -> tuple[float, float]:
        return (settings.nvidia_price_per_mtok_input, settings.nvidia_price_per_mtok_output)

    def _build_chat(self, model: str) -> Any:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:  # pragma: no cover
            raise IntegrationError(
                "langchain-openai is not installed; it is the OpenAI-compatible transport "
                "NIM speaks. Set LLM_PROVIDER=fake to run offline."
            ) from exc

        return ChatOpenAI(
            model=model,
            base_url=settings.nvidia_base_url,
            # A self-hosted NIM container is usually unauthenticated, but the
            # OpenAI client refuses to start without *some* key.
            api_key=settings.nvidia_api_key or "not-required",
            temperature=settings.llm_temperature,
            timeout=settings.llm_timeout_seconds,
            max_retries=0,  # we own the retry loop so we can log each attempt
            max_tokens=8192,
        )


class HeuristicLLM(LLMClient):
    """Deterministic stand-in used when ``LLM_PROVIDER=fake``.

    It is not a mock that returns canned blobs — it actually reads the evidence
    passed in the prompt context and applies documented SRE heuristics, so the
    graph, the policy engine and the verification loop are all exercised for
    real. What it does *not* do is reason about novel situations; that is the
    difference the eval suite measures between fake and live runs.
    """

    def __init__(self) -> None:
        from app.agents.heuristics import HeuristicEngine

        self._engine = HeuristicEngine()

    @property
    def model_name(self) -> str:
        return "heuristic-offline"

    async def structured(
        self,
        *,
        schema: type[T],
        system: str,
        user: str,
        purpose: str,
        fast: bool = False,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[T, LLMUsage]:
        started = time.perf_counter()
        payload = self._engine.respond(schema=schema, purpose=purpose, context=context or {})
        try:
            value = schema.model_validate(payload)
        except ValidationError as exc:  # pragma: no cover - engine bug, not model output
            raise IntegrationError(
                f"heuristic engine produced invalid {schema.__name__}: {exc}",
            ) from exc
        usage = LLMUsage(
            prompt_tokens=len(system) // 4 + len(user) // 4,
            completion_tokens=200,
            cost_usd=0.0,
            model=self.model_name,
            latency_ms=int((time.perf_counter() - started) * 1000),
            calls=1,
        )
        return value, usage


PROVIDERS: dict[str, type[LLMClient]] = {
    "fake": HeuristicLLM,
    "anthropic": AnthropicLLM,
    "nvidia": NvidiaLLM,
}

_client: LLMClient | None = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        try:
            factory = PROVIDERS[settings.llm_provider]
        except KeyError as exc:  # pragma: no cover - Settings already constrains this
            raise IntegrationError(
                f"unknown LLM_PROVIDER '{settings.llm_provider}'; "
                f"expected one of {', '.join(sorted(PROVIDERS))}"
            ) from exc
        _client = factory()
        log.info("llm.configured", provider=settings.llm_provider, model=_client.model_name)
    return _client


def reset_llm() -> None:
    """Test hook."""
    global _client
    _client = None
