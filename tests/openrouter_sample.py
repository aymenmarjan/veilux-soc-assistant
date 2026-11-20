"""Sample OpenRouter /models entries shared by the backend and browser tests."""


def openrouter_model(model_id, name, prompt="0", completion="0", output=("text",), created=1780000000, **extra):
    return {"id": model_id, "name": name, "created": created, "description": name + " synthetic description.",
            "context_length": extra.pop("context", 131072), "pricing": {"prompt": prompt, "completion": completion},
            "architecture": {"input_modalities": list(extra.pop("inputs", ("text",))), "output_modalities": list(output)},
            "top_provider": {"max_completion_tokens": 8192, "is_moderated": False},
            "supported_parameters": ["max_tokens", "temperature", "tools"], "endpoints": ["/api/v1/chat/completions"], **extra}


# Shapes taken from OpenRouter's real /models list: a ":free" model, a free one
# without the suffix, a music model, a variable-price router, a paid and an expired model.
OPENROUTER_MODELS = [
    openrouter_model("vendor/alpha:free", "Vendor: Alpha (free)", context=262144, reasoning={"mandatory": True}),
    openrouter_model("vendor/beta-vision:free", "Vendor: Beta Vision (free)", inputs=("text", "image"), created=1790000000),
    openrouter_model("stealth/unnamed", "Stealth model", context=1048576),
    openrouter_model("vendor/music", "Vendor: Music", output=("text", "audio")),
    openrouter_model("openrouter/auto", "Auto router", prompt="-1", completion="-1"),
    openrouter_model("vendor/paid", "Vendor: Paid", prompt="0.000001", completion="0.000002"),
    openrouter_model("vendor/gone:free", "Vendor: Gone (free)", expiration_date="2020-01-01"),
]
