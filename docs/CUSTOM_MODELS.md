# Your own AI models

Besides the built-in providers, VEILUX can use any model reachable through an
OpenAI-compatible, Claude (Anthropic Messages) or Google Gemini API, including
a company gateway or a model running on your own computer.

## Adding a model


1. Open **Settings → AI models → Your AI models → Add a model**.
2. Choose **Model service**. This fills in the service's connection details.
3. Give it a **Name in VEILUX**, paste the exact **Model ID** available to your
   account, and enter the **API key**. Local services can work without a key.
   **Load models** next to Model ID asks the service for its model list and
   offers the IDs as suggestions. It works when the Service URL ends in
   `/chat/completions` (OpenAI-compatible, including Ollama and LM Studio),
   `/messages` (Claude) or is a Gemini `/models/{model}` address; only the key and
   any extra headers are sent, never logs. Azure OpenAI deployments have no such
   list: enter the deployment's model ID yourself.
4. Use **Test connection**, then **Save model**. The model appears in the popup's
   AI provider list. This editor saves independently of the general Save settings
   button.

**Connection details** lets you change the Service URL and Connection type. The
supported types are OpenAI-compatible Chat Completions, Claude/Anthropic Messages,
and Google Gemini GenerateContent. A company gateway may require a different type
from the model's original provider. Presets supply connection information without
assuming that a particular model ID is available to your account. Gemini's URL
contains `{model}`, which is replaced with the Model ID. The API key is sent in
the `x-goog-api-key` header, never in the address; a gateway that only accepts
the key in the address can have it written into the Service URL as `?key=…`.

**Advanced settings** is optional:

- **Response style** is the API's temperature. Leave blank to use the model's
  default. Zero remains an explicit value. If the service explicitly reports
  this parameter as deprecated or unsupported, VEILUX retries without it.
- **Response length limit** is the maximum output token count, including any
  reasoning tokens counted by that service. Blank means 4,000. The connection
  test uses the same configured limit as analysis; reasoning models may need more.
- **Extra request headers** is for service-specific requirements. Enter a JSON
  object with text values, or leave it empty.

Invalid URLs, response settings and headers are reported beside their fields.
Collapsed sections open to show errors. Service errors show a readable message
with guidance for authentication, access, missing models and rate limits.

## Compatibility behaviour

- A blank **Response style** is never sent, so models that reject a
  temperature work without changes. This follows
  [Anthropic's recommendation to omit temperature for newer models](https://platform.claude.com/docs/en/about-claude/model-deprecations).
- If a service explicitly reports the temperature as unsupported, or asks for
  `max_completion_tokens` instead of `max_tokens`, VEILUX adjusts that one
  parameter and retries, at most three attempts within the same deadline. The
  model, address, key, protected prompt and response cap never change, and
  authentication, rate-limit and server errors are not retried.
- Test connection and analysis use the same settings, including the response
  length limit.
- Answers made of several blocks are joined; reasoning or "thinking" blocks are
  skipped. A reply with only reasoning explains that the response limit or the
  connection type may need changing.

These behaviours are covered by tests with mocked services; they do not prove
compatibility with every model or API variant.
