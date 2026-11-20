/* One request mapping for model testing and real analysis. No network calls. */
window.VeiluxCustomModels = (() => {
  function requestConfig(profile) {
    const result = {
      name: profile.name, api_format: profile.apiFormat || 'openai',
      endpoint: profile.endpoint, model: profile.model,
      max_tokens: profile.maxTokens === '' || profile.maxTokens == null ? 4000 : Number(profile.maxTokens),
      extra_headers: profile.extraHeaders || null
    };
    if (!Number.isInteger(result.max_tokens) || result.max_tokens < 1) throw new Error('Response length must be a positive whole number. Edit this model in Settings.');
    if (profile.temperature !== '' && profile.temperature != null) {
      const value = Number(profile.temperature);
      if (!Number.isFinite(value) || value < 0 || value > 2) throw new Error('Response style must be between 0 and 2, or blank for the model default. Edit this model in Settings.');
      result.temperature = value;
    }
    return result;
  }
  function errorMessage(data, status) {
    const detail = data?.detail ?? data?.error?.message;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) return detail.map(item => item.msg || 'Invalid model setting').join('; ');
    return 'The service could not complete the test (HTTP ' + status + '). Check the connection details.';
  }
  return { requestConfig, errorMessage };
})();
