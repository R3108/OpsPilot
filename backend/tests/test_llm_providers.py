"""Provider selection and the shared LangChain call loop.

No network: the providers' transports are replaced at the one seam that touches
them (`_build_chat`), so the retry budget, the schema-repair prompt and the
usage accounting are exercised as shipped.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from app.agents import llm as llm_module
from app.agents.llm import (
    PROVIDERS,
    AnthropicLLM,
    HeuristicLLM,
    NvidiaLLM,
    _LangChainLLM,
    get_llm,
    reset_llm,
)
from app.core.config import Settings, settings
from app.core.errors import IntegrationError


class Verdict(BaseModel):
    summary: str
    confidence: float


class _RawMessage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.usage_metadata = {"input_tokens": input_tokens, "output_tokens": output_tokens}


def _ok(value: Verdict, *, input_tokens: int = 1000, output_tokens: int = 500) -> dict[str, Any]:
    return {"parsed": value, "raw": _RawMessage(input_tokens, output_tokens)}


def _schema_violation() -> dict[str, Any]:
    return {"parsed": None, "raw": _RawMessage(10, 10), "parsing_error": "confidence: not a float"}


class _StubChat:
    """Stands in for a LangChain chat model bound to a schema."""

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.invocations: list[list[Any]] = []
        self.bind_kwargs: dict[str, Any] = {}

    def with_structured_output(self, schema: type[BaseModel], **kwargs: Any) -> _StubChat:
        self.bind_kwargs = kwargs
        return self

    async def ainvoke(self, messages: list[Any], config: dict[str, Any] | None = None) -> Any:
        self.invocations.append(messages)
        result = self._responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class _StubLLM(_LangChainLLM):
    """A provider whose only real part is the shared loop under test."""

    def __init__(self, responses: list[Any], *, method: str | None = None) -> None:
        super().__init__()
        self.structured_output_method = method  # type: ignore[misc]
        self.chat = _StubChat(responses)

    def _model_id(self, *, fast: bool) -> str:
        return "stub-fast" if fast else "stub-default"

    def _build_chat(self, model: str) -> Any:
        return self.chat


async def _call(client: _LangChainLLM, **kwargs: Any) -> Any:
    return await client.structured(
        schema=Verdict, system="sys", user="user", purpose="triage", **kwargs
    )


# -- provider selection ---------------------------------------------------


def test_every_configurable_provider_is_registered() -> None:
    """Settings and the registry must not drift apart."""
    configurable = set(Settings.model_fields["llm_provider"].annotation.__args__)  # type: ignore[union-attr]
    assert configurable == set(PROVIDERS)


@pytest.mark.parametrize(
    ("provider", "expected"),
    [("fake", HeuristicLLM), ("anthropic", AnthropicLLM), ("nvidia", NvidiaLLM)],
)
def test_get_llm_selects_the_configured_provider(
    monkeypatch: pytest.MonkeyPatch, provider: str, expected: type
) -> None:
    monkeypatch.setattr(settings, "llm_provider", provider)
    reset_llm()
    try:
        assert isinstance(get_llm(), expected)
    finally:
        reset_llm()


def test_unknown_provider_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_provider", "bedrock")
    reset_llm()
    try:
        with pytest.raises(IntegrationError, match="unknown LLM_PROVIDER"):
            get_llm()
    finally:
        reset_llm()


# -- the shared call loop -------------------------------------------------


async def test_structured_returns_parsed_value_and_usage() -> None:
    client = _StubLLM([_ok(Verdict(summary="disk full", confidence=0.9))])

    value, usage = await _call(client)

    assert value.summary == "disk full"
    assert (usage.prompt_tokens, usage.completion_tokens, usage.calls) == (1000, 500, 1)
    assert usage.model == "stub-default"


async def test_schema_violation_is_retried_with_the_error_fed_back() -> None:
    client = _StubLLM([_schema_violation(), _ok(Verdict(summary="ok", confidence=0.5))])

    value, usage = await _call(client)

    assert value.summary == "ok"
    assert len(client.chat.invocations) == 2
    repair_prompt = client.chat.invocations[1][-1].content
    assert "did not match the required schema" in repair_prompt
    assert "confidence: not a float" in repair_prompt
    # Only the successful attempt is billed to the caller.
    assert usage.calls == 1


async def test_transport_errors_are_retried_then_surface_as_integration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_max_retries", 3)
    client = _StubLLM([RuntimeError("502 bad gateway")] * 3)

    with pytest.raises(IntegrationError, match="failed after 3 attempts"):
        await _call(client)

    assert len(client.chat.invocations) == 3


async def test_fast_flag_selects_the_fast_model() -> None:
    client = _StubLLM([_ok(Verdict(summary="quick", confidence=0.2))])

    _, usage = await _call(client, fast=True)

    assert usage.model == "stub-fast"


async def test_structured_output_method_is_only_bound_when_a_provider_asks() -> None:
    default = _StubLLM([_ok(Verdict(summary="a", confidence=0.1))])
    await _call(default)
    assert "method" not in default.chat.bind_kwargs

    guided = _StubLLM([_ok(Verdict(summary="b", confidence=0.1))], method="json_schema")
    await _call(guided)
    assert guided.chat.bind_kwargs["method"] == "json_schema"


# -- nvidia nim -----------------------------------------------------------


def test_nvidia_reads_its_own_models_not_the_anthropic_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "nvidia_model", "openai/gpt-oss-120b")
    monkeypatch.setattr(settings, "nvidia_model_fast", "nvidia/nemotron-3.5-lightning-30b-a3b")
    client = NvidiaLLM()

    assert client.model_name == "openai/gpt-oss-120b"
    assert client._model_id(fast=True) == "nvidia/nemotron-3.5-lightning-30b-a3b"
    assert client.structured_output_method == settings.nvidia_structured_output_method


async def test_nvidia_costs_come_from_configured_rates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "nvidia_price_per_mtok_input", 0.2)
    monkeypatch.setattr(settings, "nvidia_price_per_mtok_output", 0.6)

    client = NvidiaLLM()
    monkeypatch.setattr(
        client, "_build_chat", lambda model: _StubChat([_ok(Verdict(summary="x", confidence=0.4))])
    )

    _, usage = await _call(client)

    # 1000 in @ $0.20/M + 500 out @ $0.60/M
    assert usage.cost_usd == pytest.approx(0.0005)


def test_a_self_hosted_nim_is_not_treated_as_the_hosted_catalogue() -> None:
    assert Settings(nvidia_base_url="https://integrate.api.nvidia.com/v1").nvidia_is_hosted
    assert not Settings(nvidia_base_url="http://localhost:8000/v1").nvidia_is_hosted


def _production(**overrides: Any) -> Settings:
    fields: dict[str, Any] = {
        "environment": "production",
        "secret_key": "a" * 40,
        "encryption_key": "k" * 44,
        "cors_origins": "https://opspilot.example.com",
        "database_url": "postgresql+asyncpg://opspilot:secret@postgres:5432/opspilot",
        "checkpoint_database_url": "postgresql://opspilot:secret@postgres:5432/opspilot",
        "redis_url": "redis://redis:6379/0",
    }
    fields.update(overrides)
    return Settings(**fields)


def test_production_requires_a_key_for_the_hosted_nim_catalogue() -> None:
    with pytest.raises(RuntimeError, match="NVIDIA_API_KEY is required"):
        _production(llm_provider="nvidia", nvidia_api_key="").validate_production()


def test_production_allows_a_self_hosted_nim_without_a_key() -> None:
    _production(
        llm_provider="nvidia",
        nvidia_api_key="",
        nvidia_base_url="http://nim.internal:8000/v1",
    ).validate_production()


def test_production_does_not_demand_an_anthropic_key_when_running_on_nim() -> None:
    _production(
        llm_provider="nvidia",
        nvidia_api_key="nvapi-test",
        anthropic_api_key="",
    ).validate_production()


def test_production_rejects_localhost_data_urls() -> None:
    with pytest.raises(RuntimeError, match="DATABASE_URL must not point at localhost"):
        _production(
            database_url="postgresql+asyncpg://opspilot:x@localhost:5432/opspilot"
        ).validate_production()


def test_module_exposes_the_providers_registry() -> None:
    assert llm_module.PROVIDERS["nvidia"] is NvidiaLLM
