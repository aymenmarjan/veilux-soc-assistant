# Statistics: protection and Changes

**Extract statistics** summarizes the configured records, the logs already
captured, or the current search shown in an Inspector panel: which fields appear and
their most frequent values. Statistics are calculated locally.

## What is protected before sending

- Statistics go through the same sanitization settings as logs before any AI
  request. Credential protection runs even when optional privacy masking is off.
- Each value keeps its real field name (`fields[].field`) for protection, so
  field rules such as `password`, `Authorization` or `Cookie`, and the
  statistics field names listed in Settings, apply to the values of that field
  only, never to counts, percentages, the query or neighbouring fields.
- Values keep their types: booleans, nulls and numbers are protected as values,
  arrays at each item, and the original shape is restored afterwards. A hidden
  value that happens to equal a count does not hide the count.
- Credential protection takes precedence over restorable privacy masking.

## What you see

- The statistics panel keeps the local originals; it is not a preview of what
  is sent.
- Results → **Sanitized** includes a read-only preview of the statistics as
  they were prepared for the request, with a copy button. With privacy masking
  off, this preview can still contain ordinary private values.
- **Changes** combines the privacy replacements from logs, case notes and
  statistics. Credential placeholders are listed with a protected-secret label;
  their originals are never shown or restored. **Copy changes** uses the same
  list.
- The backend returns `sanitized_field_statistics` separately; sanitize-only
  responses also append the statistics to `sanitized_log` for older clients.

## Clearing

- **Clear all statistics** removes statistics and keeps the logs.
- **Clear all inputs & results** removes logs, statistics, notes and results
  for the case. Saved connections, keys and preferences stay.

Protection is applied when you analyze or sanitize; extracting statistics alone
does not change the local originals or fill in Changes.
