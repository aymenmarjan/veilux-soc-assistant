# IP and domain enrichment

## Using it

Update the backend and the complete extension together. In the backend folder,
run `python -m pip install -r requirements.txt`, then restart the backend.
Reload the unpacked extension from the same folder to retain its saved settings.
This update adds `tldextract` and the extension's `threat_intel.js`.

- For a single indicator, open **Tools → Check IOC**, choose lookup sources,
  enter the IP address or domain, then click **Check**. WHOIS / RDAP works with
  no key. Manual checks request fresh data, even if automatic enrichment is off.
- Add reputation keys in **Settings → Threat Intelligence**. **Test Threat Intel
  Keys** makes fresh checks of just the entered keys; a WHOIS result cannot make
  a rejected key look successful. These checks use `8.8.8.8` and consume quota.
- During AI analysis, enable **Threat intelligence** and choose its sources.
  Those source choices are shared with the manual tool. Results appear under
  **Threat intel**, with a separate, collapsible card for each service. Lookup
  failures, skipped sources, cached results and check timestamps are visible.

Provider cards start **collapsed**; click a provider name to expand it. Both
**Copy threat intelligence** buttons include the full details even when cards
are closed. ISP, network-owner and other declared descriptive fields retain
their metadata context during protection, so labels such as `EXAMPLE-FIBRE-QXRVLT02`
are not hidden solely because they resemble random tokens. Credential detectors,
known secrets, explicit hides and GUID/hash handling still apply.

Automatic IP/hostname privacy masking protects the AI prompt without disabling
enabled public TI lookups. Lookup services receive the eligible indicator's real
value; they do not receive the complete log. Credentials, explicit hides and
internal-network/domain exclusions still block dispatch. **Changes** lists AI
privacy replacements; an entry there alone does not mean the value was excluded
from TI.

When there are no results, the Threat intel tab explains whether enrichment was
off, the run was local-only, no source was configured, no supported eligible
indicators remained, or services failed. Internal addresses such as `192.168.x.x`
and `10.x.x` intentionally receive no public reputation lookup. Configured internal
ranges and domains stay excluded even with optional AI privacy masking off.

## What each service supplies

| Service | Applies to | Displayed information |
| --- | --- | --- |
| AbuseIPDB | IPv4 and IPv6 | Abuse confidence, reports in the last 90 days, distinct reporters, last report date, ISP, usage type, domain, country name/code, hostnames, IP version, public/whitelisted/Tor flags |
| VirusTotal | IP, domain, URL | Malicious and suspicious engine counts, total reporting engines, analysis time, ASN, network owner/range, country, registry, community reputation, categories and tags when returned |
| VirusTotal | MD5, SHA-1, SHA-256 | Engine counts, analysis time, file name/type/size, first submission time, submission count, community reputation and tags when returned |
| WHOIS / RDAP | IP and domain | IP network name, organization, range/CIDR, registry country, assignment date and abuse contact; domain registrar, registration/expiry/change dates, age, nameservers, status and abuse contact |

The [documented AbuseIPDB check API](https://docs.abuseipdb.com/#check-endpoint)
does **not** expose ASN or city and lists no WHOIS endpoint. This implementation
does not scrape its website or invent those fields. ASN comes from a separately
enabled [VirusTotal lookup](https://docs.virustotal.com/reference/ip-object), if
returned. City/region is labelled unavailable. WHOIS comes from the free RDAP
registration service; registry country and an owner's address are not the IP's
physical location. Some registries do not provide RDAP or redact contact data.

AbuseIPDB's [Individual free plan](https://www.abuseipdb.com/pricing) lists 1,000
IP checks/reports per day as checked on 2026-10-12. It requires a developer API
key. `verbose` is requested for the country name; individual report comments
are discarded. Counts apply to the configured 90-day window and may differ
from the website's window or a later lookup. A real score of **0%** remains 0;
a missing or malformed score is **unknown**. Neither 0% nor a WHOIS record is
evidence that an indicator is safe.

Hashes approved with **Keep** retain their identity when VirusTotal uses lowercase
hexadecimal. Credential evidence or an explicit hide still takes precedence.
The report link targets the eligible digest; links containing protection markers
are suppressed.

An explicitly labelled `IMPHASH` in Sysmon's hash list is shown as **not queried**.
It describes imported functions and cannot use the same exact-file lookup as
MD5, SHA-1 or SHA-256. VirusTotal Intelligence searches are not used.
See the official [file lookup API](https://docs.virustotal.com/reference/file-info),
[file attributes](https://docs.virustotal.com/reference/files) and
[search modifiers](https://docs.virustotal.com/docs/file-search-modifiers).
Bare 32-character hashes have no algorithm label and remain MD5 candidates.

## How lookups behave

Provider results have independent 24-hour caches, keyed by source, indicator
and a credential fingerprint. Raw API keys are not written to the cache.
Only successful source responses are
cached, including WHOIS; failed sources retry next time. An explicit refresh
that fails invalidates that source's previous success. `use_cache: false` is
supported by `/threat-intel/lookup` and used by manual Check and Test Keys.

For RDAP, subdomains use the registrable domain from the bundled Public Suffix
List (including multi-label suffixes such as `co.uk`). The requested hostname
and actual registration lookup domain are both displayed. VirusTotal still
checks the full hostname. PSL retrieval is disabled during lookups; update the
dependency to refresh its bundled snapshot. URL path/query case is preserved
in cache and deduplication identities. Missing RDAP records mean unavailable
registration data, not proof of non-registration.

Sources for one indicator run concurrently, with a maximum 15-second deadline
per source. Automatic enrichment retains its 45-second overall budget and
50-indicator cap (25 per type); it does not increase provider quotas. A slow
source yields a timeout while completed results remain available. No new
provider calls start after the budget expires; available cached results can
still be used. Remaining sources are labelled skipped. Cancelling the parent
request propagates to in-progress lookups.

Secret protection, explicit privacy hides and internal-network exclusions
still precede automatic provider dispatch. Sanitize-only mode remains local.
Notable signals include selected provider metadata in the AI context through
the existing sanitization pipeline. All findings, including unknown and
unflagged results, are available in the structured response and UI. Manual
lookup preserves its credential/explicit-hide preflight checks. Provider text
is HTML-escaped, and report links allow only HTTPS on the expected provider
host; arbitrary returned URLs are not rendered as links.

All provider and AI calls in the tests are mocked. They cover the
`/threat-intel/lookup` and `/analyze` boundaries, caching, key changes, missing
data, IPv6, multi-label domain suffixes, CIDR, URL case and cancellation; they
do not establish coverage of every provider or registry variation.
