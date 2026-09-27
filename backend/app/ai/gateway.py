"""Model gateway.

Two providers, split by capability rather than preference:

  generation  DeepSeek or Gemini, selected by AI_PROVIDER. The explanation step
              is the only place a model is asked to write anything, so it is the
              only place worth making swappable.
  embedding   Gemini, always. DeepSeek publishes no embedding endpoint, and the
              corpus vectors have to come from one consistent space or
              retrieval silently degrades.

The google-generativeai SDK is synchronous, so its calls are pushed onto a
worker thread. Without that, one embedding call would block the event loop and
stall concurrent scans. DeepSeek is reached over its OpenAI-compatible REST API
with httpx, which is already async.
"""

import asyncio
import json
import logging
import math
import re

import google.generativeai as genai
import httpx
from google.api_core import exceptions as google_exceptions

from app.config import settings

logger = logging.getLogger(__name__)

_configured = False


class AIUnavailableError(RuntimeError):
    pass


class AIResponseTruncatedError(RuntimeError):
    """The model hit the output cap before finishing its JSON object.

    Worth its own type: the caller can say so instead of reporting a generic
    parse failure, which sends whoever reads the finding looking in the wrong
    place.
    """


# finish_reason values from the Gemini API. 1 is a normal stop.
_FINISH_MAX_TOKENS = 2


def _ensure_configured() -> None:
    """Configure the embedding client. Embeddings are Gemini only."""
    global _configured
    if not settings.embedding_enabled:
        raise AIUnavailableError("GEMINI_API_KEY is not set (needed for embeddings)")
    if not _configured:
        genai.configure(api_key=settings.gemini_api_key)
        _configured = True


def _retry_delay_seconds(exc: Exception) -> float | None:
    """Seconds the API asked us to wait, when it said so.

    A 429 carries a RetryInfo with the real window. Honouring it beats guessing,
    because the free tier's per-minute quota can leave nearly a minute to run.
    """
    for attr in ("retry_delay", "retry_after"):
        info = getattr(exc, attr, None)
        seconds = getattr(info, "seconds", None)
        if seconds:
            return float(seconds)
    match = re.search(r"retry_delay\s*{\s*seconds:\s*(\d+)", str(exc))
    return float(match.group(1)) if match else None


async def _with_retry(call, *, what: str):
    """Run a blocking SDK call on a worker thread, retrying on quota errors.

    A scan issues one generation per non-compliant rule in quick succession.
    On a rate-limited key that is enough to trip the per-minute quota partway
    through, which would silently leave most findings unexplained.
    """
    last: Exception | None = None
    for attempt in range(settings.gemini_max_retries):
        try:
            return await asyncio.to_thread(call)
        except google_exceptions.ResourceExhausted as exc:
            last = exc
            if attempt == settings.gemini_max_retries - 1:
                break
            delay = _retry_delay_seconds(exc) or (2.0 ** attempt)
            delay = min(delay + 1.0, settings.gemini_max_retry_wait)
            logger.warning(
                "%s hit the quota, waiting %.0fs (attempt %d/%d)",
                what,
                delay,
                attempt + 1,
                settings.gemini_max_retries,
            )
            await asyncio.sleep(delay)
        except (
            google_exceptions.ServiceUnavailable,
            google_exceptions.DeadlineExceeded,
            google_exceptions.InternalServerError,
        ) as exc:
            last = exc
            if attempt == settings.gemini_max_retries - 1:
                break
            await asyncio.sleep(min(2.0**attempt, settings.gemini_max_retry_wait))
    raise last if last else RuntimeError(f"{what} failed with no exception recorded")


async def generate_text(prompt: str, *, system_instruction: str | None = None) -> str:
    if settings.ai_provider == "deepseek":
        return await _generate_deepseek(prompt, system_instruction=system_instruction)
    return await _generate_gemini(prompt, system_instruction=system_instruction)


async def _generate_deepseek(
    prompt: str, *, system_instruction: str | None = None
) -> str:
    if not settings.deepseek_api_key:
        raise AIUnavailableError("DEEPSEEK_API_KEY is not set")

    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": settings.deepseek_model,
        "messages": messages,
        "temperature": settings.gemini_temperature,
        "max_tokens": settings.gemini_max_output_tokens,
        # Same contract as the Gemini path: the caller parses one JSON object.
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {settings.deepseek_api_key}"}

    last: Exception | None = None
    async with httpx.AsyncClient(
        base_url=settings.deepseek_base_url, timeout=180.0
    ) as client:
        for attempt in range(settings.gemini_max_retries):
            try:
                response = await client.post(
                    "/chat/completions", json=payload, headers=headers
                )
                if response.status_code == 429 or response.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"{response.status_code}: {response.text[:200]}",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                body = response.json()

                choice = (body.get("choices") or [{}])[0]
                if choice.get("finish_reason") == "length":
                    raise AIResponseTruncatedError(
                        f"model hit the {settings.gemini_max_output_tokens} token "
                        f"output cap before completing its response "
                        f"(usage: {body.get('usage')})"
                    )
                return (choice.get("message") or {}).get("content") or ""

            except (httpx.HTTPStatusError, httpx.TransportError) as exc:
                last = exc
                if attempt == settings.gemini_max_retries - 1:
                    break
                delay = min(2.0**attempt, settings.gemini_max_retry_wait)
                logger.warning(
                    "DeepSeek generation failed (%s), retrying in %.0fs (%d/%d)",
                    type(exc).__name__,
                    delay,
                    attempt + 1,
                    settings.gemini_max_retries,
                )
                await asyncio.sleep(delay)

    raise last if last else RuntimeError("DeepSeek generation failed with no exception")


async def _generate_gemini(
    prompt: str, *, system_instruction: str | None = None
) -> str:
    _ensure_configured()

    def _call() -> str:
        model = genai.GenerativeModel(
            settings.gemini_model, system_instruction=system_instruction
        )
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=settings.gemini_temperature,
                max_output_tokens=settings.gemini_max_output_tokens,
                response_mime_type="application/json",
            ),
        )

        # gemini-2.5-flash spends output budget on internal reasoning before it
        # emits anything, and that reasoning counts against max_output_tokens.
        # A long prompt can therefore exhaust the cap mid-object and return
        # JSON that simply stops, which looks identical to a malformed reply.
        candidate = response.candidates[0] if response.candidates else None
        if candidate is not None and candidate.finish_reason == _FINISH_MAX_TOKENS:
            usage = getattr(response, "usage_metadata", None)
            raise AIResponseTruncatedError(
                f"model hit the {settings.gemini_max_output_tokens} token output cap "
                f"before completing its response (usage: {usage})"
            )

        try:
            return response.text or ""
        except ValueError as exc:
            # The SDK raises rather than returning when a candidate carries no
            # usable text part, for instance when it was stopped by a filter.
            reason = getattr(candidate, "finish_reason", "unknown")
            raise AIResponseTruncatedError(
                f"model returned no usable text (finish_reason={reason})"
            ) from exc

    return await _with_retry(_call, what="generation")


def _normalise(vector: list[float]) -> list[float]:
    """Scale to unit length.

    Truncating a Matryoshka embedding from its native 3072 dimensions down to
    768 leaves the vector well short of unit length, around 0.58 in practice.
    Cosine distance is magnitude invariant so retrieval still ranks correctly,
    but storing unit vectors keeps the similarity scores comparable across
    re-indexes and keeps the door open to a distance metric that is not.
    """
    magnitude = math.sqrt(sum(x * x for x in vector))
    if magnitude == 0:
        return vector
    return [x / magnitude for x in vector]


async def embed(text: str, *, task_type: str = "retrieval_document") -> list[float]:
    _ensure_configured()

    def _call() -> list[float]:
        result = genai.embed_content(
            model=f"models/{settings.gemini_embedding_model}",
            content=text,
            task_type=task_type,
            output_dimensionality=settings.gemini_embedding_dim,
        )
        return _normalise(list(result["embedding"]))

    return await _with_retry(_call, what="embedding")


async def embed_batch(
    texts: list[str], *, task_type: str = "retrieval_document"
) -> list[list[float]]:
    _ensure_configured()

    def _call() -> list[list[float]]:
        result = genai.embed_content(
            model=f"models/{settings.gemini_embedding_model}",
            content=texts,
            task_type=task_type,
            output_dimensionality=settings.gemini_embedding_dim,
        )
        return [_normalise(list(v)) for v in result["embedding"]]

    return await _with_retry(_call, what="batch embedding")


# Anchored at the start on purpose. An unanchored search matches a fence that
# the model put INSIDE a JSON string, which is routine here because the prompt
# asks for a code snippet in suggested_fix. Extracting that inner fence turns a
# perfectly valid response into an unparseable one.
_WRAPPING_FENCE = re.compile(r"\A```(?:json)?\s*(.*?)\s*```\Z", re.DOTALL)


def parse_json_response(raw: str) -> dict | list | None:
    """Parse a model response into JSON, tolerating a markdown wrapper.

    Tries the text as-is first. Most responses are already valid JSON, and any
    rewriting before that point risks corrupting one that was fine.
    """
    if not raw or not raw.strip():
        return None

    candidate = raw.strip()

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    fenced = _WRAPPING_FENCE.match(candidate)
    if fenced:
        candidate = fenced.group(1)

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        starts = [i for i in (candidate.find("{"), candidate.find("[")) if i != -1]
        start = min(starts) if starts else -1
        end = max(candidate.rfind("}"), candidate.rfind("]"))
        if start == -1 or end <= start:
            logger.warning("Could not parse model response as JSON")
            return None
        try:
            return json.loads(candidate[start : end + 1])
        except json.JSONDecodeError:
            logger.warning("Could not parse model response as JSON after trimming")
            return None
