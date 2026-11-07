"""OpenAI / OpenAI-compatible provider.

Works with the official OpenAI API and any compatible gateway (Azure OpenAI,
OpenRouter, Together, vLLM's OpenAI server, ...) by setting ``base_url``.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Optional

from dbmask.llm.base import SYSTEM_PROMPT, LLMProvider, LLMResult


class OpenAIProvider(LLMProvider):
    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.0,
        timeout: int = 60,
    ):
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "The 'openai' package is required for OpenAIProvider. "
                "Install it with: pip install 'dbmask[openai]'"
            ) from exc

        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self._client = OpenAI(api_key=api_key, base_url=base_url)

        # Optional token counting; safe if tiktoken is missing.
        try:
            import tiktoken

            try:
                self._encoding: Optional[tiktoken.Encoding] = tiktoken.encoding_for_model(model)
            except KeyError:
                self._encoding = tiktoken.get_encoding("cl100k_base")
        except ImportError:  # pragma: no cover
            self._encoding = None

    def _count(self, text: str) -> int:
        if not self._encoding or not text:
            return 0
        return len(self._encoding.encode(text))

    def classify(self, column_name: str, sample: Sequence[str]) -> LLMResult:
        prompt = self.build_prompt(column_name, sample)
        response = self._client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            timeout=self.timeout,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        content = response.choices[0].message.content or ""
        result = self.parse_response(content)

        # Prefer the API's own usage numbers; fall back to local counting.
        usage = getattr(response, "usage", None)
        if usage and getattr(usage, "total_tokens", None):
            result.token_usage = usage.total_tokens
        else:
            result.token_usage = self._count(SYSTEM_PROMPT) + self._count(prompt) + self._count(content)
        return result
