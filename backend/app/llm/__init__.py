from app.config import settings
from app.llm.base_provider import BaseLLMProvider, LLMResponse
from app.llm.google_provider import GoogleProvider, OpenAIProvider, AnthropicProvider, LocalProvider

def get_llm_provider(provider_type: str = None, model: str = None) -> BaseLLMProvider:
    provider = provider_type or settings.LLM_PROVIDER
    if provider.lower() in ["google", "gemini"]:
        return GoogleProvider(model=model or settings.LLM_MODEL)
    elif provider.lower() == "openai":
        return OpenAIProvider(model=model or "gpt-4o")
    elif provider.lower() == "anthropic":
        return AnthropicProvider(model=model or "claude-3-5-sonnet-20241022")
    else:
        return LocalProvider(url=settings.LOCAL_LLM_URL, model=model or "llama3")
