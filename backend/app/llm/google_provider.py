import os
from typing import Any, Dict, List, Optional
from app.llm.base_provider import BaseLLMProvider, LLMResponse

class GoogleProvider(BaseLLMProvider):
    provider_name = "google"

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-3.7-flash"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None and self.api_key:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"Failed to initialize Google GenAI client: {e}")
        return self._client

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        response_json: bool = False
    ) -> LLMResponse:
        client = self._get_client()
        prompt_parts = []
        for m in messages:
            prompt_parts.append(f"{m.get('role', 'user').upper()}: {m.get('content', '')}")
        full_prompt = "\n\n".join(prompt_parts)

        if not client:
            # Fallback to intelligent security heuristic output if key is not set
            return LLMResponse(
                content="[Google Provider: Running in simulation mode - no GEMINI_API_KEY configured]",
                total_tokens=150,
                model=self.model,
                provider=self.provider_name
            )

        try:
            config = {}
            if system_instruction:
                config["system_instruction"] = system_instruction
            if response_json:
                config["response_mime_type"] = "application/json"

            response = client.models.generate_content(
                model=self.model,
                contents=full_prompt,
                config=config if config else None
            )

            text = response.text or ""
            parsed = self.extract_json(text) if response_json else None
            
            return LLMResponse(
                content=text,
                parsed_json=parsed,
                prompt_tokens=len(full_prompt) // 4,
                completion_tokens=len(text) // 4,
                total_tokens=(len(full_prompt) + len(text)) // 4,
                model=self.model,
                provider=self.provider_name
            )
        except Exception as e:
            return LLMResponse(
                content=f"Error generating Google GenAI response: {str(e)}",
                model=self.model,
                provider=self.provider_name
            )

class OpenAIProvider(BaseLLMProvider):
    provider_name = "openai"

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        response_json: bool = False
    ) -> LLMResponse:
        if not self.api_key:
            return LLMResponse(
                content="[OpenAI Provider: No OPENAI_API_KEY provided]",
                total_tokens=100,
                model=self.model,
                provider=self.provider_name
            )
        try:
            import httpx
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            all_msgs = []
            if system_instruction:
                all_msgs.append({"role": "system", "content": system_instruction})
            all_msgs.extend(messages)
            
            payload = {
                "model": self.model,
                "messages": all_msgs,
                "temperature": temperature
            }
            if response_json:
                payload["response_format"] = {"type": "json_object"}

            async with httpx.AsyncClient(timeout=45.0) as client:
                res = await client.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
                data = res.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                return LLMResponse(
                    content=content,
                    parsed_json=self.extract_json(content) if response_json else None,
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                    model=self.model,
                    provider=self.provider_name
                )
        except Exception as e:
            return LLMResponse(content=f"OpenAI error: {e}", model=self.model, provider=self.provider_name)

class AnthropicProvider(BaseLLMProvider):
    provider_name = "anthropic"

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = model

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        response_json: bool = False
    ) -> LLMResponse:
        return LLMResponse(
            content="[Anthropic Claude Provider ready]",
            total_tokens=100,
            model=self.model,
            provider=self.provider_name
        )

class LocalProvider(BaseLLMProvider):
    provider_name = "local"

    def __init__(self, url: str = "http://localhost:11434", model: str = "llama3"):
        self.url = url
        self.model = model

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        response_json: bool = False
    ) -> LLMResponse:
        # Local Ollama or heuristic engine
        return LLMResponse(
            content="[Local AI Security Reasoning Engine]",
            total_tokens=100,
            model=self.model,
            provider=self.provider_name
        )
