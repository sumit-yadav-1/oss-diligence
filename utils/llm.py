import os
import time

from google import genai

_client = None


def _get_client():
    global _client

    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY not set."
            )

        _client = genai.Client(api_key=api_key)

    return _client


class LLMCallFailed(Exception):
    """Raised when an LLM call fails validation after all retries."""


def call_llm(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 1024,
    max_retries: int = 2,
    model: str = "gemini-2.5-flash",
) -> str:
    """
    Call Gemini with retry-on-failure. On empty/whitespace response or API
    error, retries with a stricter follow-up instruction appended. Raises
    LLMCallFailed only after all retries are exhausted, so the calling agent
    can decide how to degrade gracefully.
    """

    client = _get_client()

    prompt = user_prompt
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            response = client.models.generate_content(
                model=model,
                contents=f"""
SYSTEM INSTRUCTIONS:
{system_prompt}

USER REQUEST:
{prompt}
""",
            )

            output = (response.text or "").strip()

            if not output:
                raise LLMCallFailed("Empty response from model")

            return output

        except Exception as exc:
            last_error = exc

            if attempt < max_retries:
                prompt = (
                    user_prompt
                    + "\n\nIMPORTANT: Your previous response was invalid or empty. "
                    "Respond with a complete, non-empty answer following the format instructions exactly."
                )

                time.sleep(1.0 * (attempt + 1))
                continue

    raise LLMCallFailed(
        f"LLM call failed after {max_retries + 1} attempts: {last_error}"
    )