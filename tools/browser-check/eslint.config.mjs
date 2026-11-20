import compat from 'eslint-plugin-compat';

// The browsers VEILUX supports: the minimum versions match extension/manifest.json
// (minimum_chrome_version and gecko.strict_min_version).
export const browsers = ['chrome >= 121', 'edge >= 121', 'opera >= 107', 'firefox >= 140'];

export default [
  { ignores: ['extension/browser-polyfill.js'] },
  {
    files: ['extension/**/*.js'],
    plugins: { compat },
    languageOptions: { ecmaVersion: 'latest', sourceType: 'script' },
    settings: { browsers, polyfills: [] },
    rules: { 'compat/compat': 'error' }
  }
];
