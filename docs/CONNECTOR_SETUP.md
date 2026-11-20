# Set up a connection

A **connection** tells VEILUX where to read logs for one SIEM or SOAR console.
Open **Settings → Connections → Add a connection**. The editor asks a few
questions in order and only shows what your answers need.

| Step | Question | Shown when |
| --- | --- | --- |
| 1. Basics | Platform template, name and website address | Always |
| 2. Where are the logs? | A table, JSON on the page, an API request, a search page's Inspector panel, or your own script | Always |
| 3. API request | Address, path, body, and where the records are in the response | API request |
| 4. Request values | Where each `${name}` in the request comes from | API request |
| 5. Sign-in | How VEILUX signs in to the API | API request |
| More options | Page matching, record limits, statistics, certificates | Collapsed |

Use **Preview extraction** with a matching page open to check the result before
you save. Preview reads your source and never calls an AI service. When a value
source reads another website (a case or profile page), Preview reads that page
even if the connection's own website is also open, and it shows which page it
read. **Test
connection** only checks that the API answers; it does not prove that records
can be read.

## 1. Basics

- **Platform template** (optional) fills in all technical settings for Splunk,
  Microsoft Sentinel, the Microsoft Defender portal, Elasticsearch, OpenSearch,
  Wazuh or IBM QRadar (see [Platform templates](#platform-templates)). Your
  name and website address are kept. Everything stays editable, and your saved
  connections are never changed when the extension updates. Choosing
  *None* clears the technical settings again.
- **Website address** is the console you open in your browser, such as
  `https://siem.example.com`. VEILUX uses the connection on that website.

## 2. Where are the logs?

Choose one:

| Choice | Use it when | What to fill in |
| --- | --- | --- |
| **A table on the page** | Results are shown as an HTML table | Nothing, or pick a specific table |
| **JSON shown on the page** | The page shows raw JSON, for example in a `<pre>` block | The element and where the records are in the JSON |
| **An API request** | The platform has a REST API | Steps 3–5 |
| **The search Inspector panel** | Your search page has an Inspector panel (OpenSearch Dashboards, Wazuh) | Nothing: the standard selectors are filled in and stay editable |
| **My own page script** | Nothing else fits | A trusted JavaScript snippet returning `{logs: [...]}` |

### Reading one specific table

With *A table on the page*, VEILUX uses the largest visible table by default.
If the page has several tables, choose **A specific table**, open the page in
another tab and click **Find tables on the open page**. Each table is listed
with its row count and column headings. Click **Use this table** and VEILUX
writes its CSS selector for you. You can also type a selector, such as
`table#events`.

Page readers only see rows that are currently displayed. Rows on other result
pages, or rows a virtual list has not rendered, are not included.

## 3. API request

- **API address** is filled from the website address. Change it only when the
  API is on another host, port or path prefix (Splunk's management port 8089,
  or an Elasticsearch cluster on port 9200, for example).
- **How the API answers**: most APIs return the records directly. Search-job
  APIs start a search, report its status, then return results; the three steps
  have their own fields.
- **Path, URL query parameters and body**: write `${name}` wherever a value from
  the page belongs, for example `/api/events/${event_id}`, and `${query}` for the
  search below.
- **Default search** fills `${query}` when the page gives no values.
- **Where are the records in the JSON?** Give the dot path to the list of
  records, such as `data.events`. Not sure? Open **Find it from a sample**,
  paste an example response, list the possible locations and preview the
  records. Responses that list column names and rows separately (Sentinel's
  `tables.0.rows`) use the *Column names and rows are listed separately*
  layout.
- Optional: **Read several pages of results** (offset or next-page token) and
  **Also read a case summary** (a second request whose fields can be used as
  `${context.field}` in a search job).

## 4. Request values

This step answers one question: *where does each `${name}` come from?* A box at
the top lists every value the request uses and marks the ones that have no
source yet. It also warns when a source captures a name the request never uses,
which usually means a typo.

Add a value from:

| Source | Use it for | Example |
| --- | --- | --- |
| **The page address** | An ID in the URL of the page you are viewing | `https://siem.example.com/events/{event_id}` |
| **Links on a page** | Record links listed on a page, such as a ticket; one request per link | Links in `.record-links` matching `https://siem.example.com/events/{event_id}` |
| **Text on a page** | An ID written on the page | `Alert (?<alert_id>\d+)` in the whole page or one element |
| **An element attribute** | An ID stored in HTML | `data-event-id` of `[data-event-id]` |
| **A fixed value** | A value that never changes | `workspace` = `1234-abcd` |

Each source (except fixed values) reads on **this connection's website** or on
**another website**, such as a ticketing or case-management tool. A new source
starts on the same website as the previous one. Enter only a hostname
(`tickets.example.com`) to match that host on any port; a full address
(`https://tickets.example.com:9000`) matches exactly. **Only when the page
address contains** narrows a source to pages such as `/ticket/`.

### Address and link patterns

The easy way is an **example address with `{names}`**: paste a real address and
replace each changing part with a name in braces.

```
https://siem.example.com/records/{index}/{doc_id}
```

For anything more complex, choose **A regular expression** and name each value
with a group:

```
/records/(?<index>[^/?#]+)/(?<doc_id>[^/?#]+)
```

Python's `(?P<name>...)` spelling also works. Captured values are URL-decoded
(`evt%2042` becomes `evt 42`) and encoded again for the request. Use **Check
example** to try a pattern on a pasted address without opening anything.

For **Links on a page**, an address pattern only accepts links to the host in
the pattern. With a regular expression, choose whether links must point to this
connection's website, any website, or another host. **Part of the page to
search** limits the search to one element, such as `.record-links`; both
`<a>` links and addresses written as plain text inside it are found.

### Text and attributes

Leave **Element** blank to search the whole page, or enter a CSS selector such as
`#description`. The **value pattern** is a regular expression with named
groups. Leave it blank to take the whole text (or attribute) as one value and
give that value a name. Under **Options** you can ignore letter case, read the
HTML source instead of visible text, decode URL-encoded values, and make one
request for each value found.

### When the page has no values

**When the current page provides none of these values** decides what happens
on a page where no source finds anything:

- *Send the request anyway* uses fixed values and the default search (useful
  when the default search stands on its own).
- *Read a table / JSON / the Inspector panel / my script instead* falls back to
  a page reader, configured in step 2, for example to read the results table
  of a search page where no single record is open.

Values on this connection's own website are optional: when none is found,
VEILUX uses this fallback. Values on another website are required by default;
untick **Required** under the source's Options to make one optional.

Use **Test on the open page** on any source to see the values it captures from a
matching open tab. It makes no API request.

When one request fails, for example HTTP 404 because a record does not exist or
the signed-in account cannot see it, VEILUX skips that record, keeps reading
the others, and names the value that failed (`For id=abc: …`). A rejected
sign-in (HTTP 401) or a redirect still stops the whole extraction.

**Copy case-platform value sources from another connection** reuses the value
sources that another connection reads on other websites, so the same setup does
not have to be entered twice.

## 5. Sign-in

| Option | Use it when |
| --- | --- |
| Use my current browser login | You are signed in to the platform in this browser (default) |
| API key or access token | You have a token; include any prefix such as `Bearer` |
| App sign-in (OAuth 2.0 client credentials) | The API issues tokens to a registered app, such as a Microsoft Entra ID app registration: enter the token address, client ID, client secret and scope |
| Username and password | The API accepts basic authentication |
| One named browser cookie | The API needs exactly one session cookie |
| No sign-in needed | The API is open |

Some platforms need login cookies repeated as headers, which is set under
**Send login cookies as headers**; a platform template fills this in when its
platform needs it.

With **App sign-in**, the local backend asks the token address for an access
token (the OAuth 2.0 client credentials grant), keeps it in memory only, asks
for a new one two minutes before it expires or after the API rejects it, and
sends it as `Authorization: Bearer`. The client secret is sent only to a
verified `https://` token address, even when certificate checks are turned off
for the API itself, and it is left out of settings exports unless you include
keys.

## More options

- **Only on addresses containing**: for several workspaces on one website.
- **Search page address contains**: picks the right table on multi-frame
  consoles, and stops page-text values being read on the search page.
- **Maximum records per extraction** (1–5,000) and **When I click Extract
  statistics** (this connection's records, the logs already captured, the
  current search in an Inspector panel, or off). How many records statistics read is set in
  the popup under **Statistics sample** (1–100,000).
- **Connection check path**, **Where API requests run** (signed-in tab or local
  backend), certificate verification, trust store, and an organization CA
  certificate (public PEM only).

## Recipes

**Records linked from another page (optional).** Step 2: *An API request*.
Path `/api/events/${event_id}`. Step 4: *Links on a page*, another website
`https://tickets.example.com`, part of the page `.record-links`, link pattern
`https://siem.example.com/events/{event_id}`. One request is made per link.

**ID in the address bar.** Step 4: *The page address*, pattern
`https://siem.example.com/alerts/{alert_id}`.

**ID written on the page.** Step 4: *Text on a page*, element `h1.title`,
pattern `Alert (?<alert_id>\d+)`.

**A specific results table.** Step 2: *A table on the page* → *A specific
table* → *Find tables on the open page* → *Use this table*.

**A KQL workspace.** Template *Microsoft Sentinel / Azure Monitor Logs: KQL
query*. Replace the fixed value `YOUR-WORKSPACE-ID` and `YOUR-TENANT-ID` in the
token address, enter the app's client ID and secret, and set the default KQL
search.

## Nothing is filled in behind your back

Every value a connection uses is visible in its form. A blank field stays
blank: there are no built-in paths, selectors, sign-in names or search-job
values. If something required is missing, the editor or the
extraction says which field to fill. Platform templates write all their values
into the form, where you can see and change them.

Connections are read in the current format only. A connection saved by a
development build before VEILUX 1.0.0 is kept in storage but not used; Settings
says how many there are and can remove them. Create such a connection again.

## Platform templates

Each template follows the vendor's public API reference. Each section says
what the template reads, the requests it makes, what you provide, and what to
check on your own deployment. VEILUX's automated tests run every template
against mock APIs that follow these references
([tests/test_platform_templates.py](../tests/test_platform_templates.py)). No
template has been tested against a live deployment by the project: API
versions, permissions and data differ between deployments, so use **Preview
extraction** before relying on one.

### Splunk

**Splunk: results of the search on screen.**
- **Reads:** the results of the search you are viewing. Splunk Web puts the
  search ID in the page address (`…/app/search/search?…&sid=1731830000.42`).
- **Requests:** `GET /services/search/v2/jobs/<sid>/results?output_mode=json`,
  in pages of 100 (`offset` and `count`, up to 5,000 records).
- **Without a search ID:** the results table on screen is read instead.
- **You provide:**
  - the console as the website;
  - the management port (usually `8089`) as the API address;
  - a token (`Bearer <token>`) of the user who ran the search, or of a user
    allowed to read it.
- **Check:**
  - Search results expire: ten minutes after an ad hoc search by default.
    After that Splunk answers *Unknown sid*, which VEILUX shows; run the search
    again.
  - The v2 results endpoint exists in Splunk Enterprise 9.0.1 and later (and
    Splunk Cloud Platform 9.0.2208 and later). For older versions, change the
    path to `/services/search/jobs/<sid>/results`.

**Splunk: run a search (SPL).**
- **Reads:** the default search, or a search typed in the popup.
- **Requests:**
  1. `POST /services/search/jobs`, with `search`, `output_mode=json`,
     `earliest_time=-24h` and `latest_time=now` in a form body, as Splunk
     documents it.
  2. `GET /services/search/jobs/<sid>?output_mode=json`, polled until
     `entry.0.content.dispatchState` is `DONE`.
  3. `GET /services/search/v2/jobs/<sid>/results`, in pages of 100.
- **If the search fails:** VEILUX shows Splunk's own error messages (from
  `entry.0.content.messages`), such as a syntax error in an `eval`.
- **Searches must start with `search`** or another generating command such as
  `| tstats`.
- **You provide:** the management-port address, and a token or username and
  password.

### Microsoft Sentinel and the Microsoft Defender portal

All three templates sign in as an app by default: register an app in Microsoft
Entra ID, create a client secret, grant the role or permission below, then
replace `YOUR-TENANT-ID` in the token address
(`https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`) and enter the
client ID and secret. **API key or access token** also works with a pasted
Bearer token, which expires after about an hour.

**Microsoft Sentinel / Azure Monitor Logs: KQL query.**
- **Requests:** `POST https://api.loganalytics.azure.com/v1/workspaces/<workspace>/query`
  with `{"query": …, "timespan": "P1D"}`.
- **Records:** column names and rows are returned separately, and VEILUX maps
  them into records.
- **Partial results:** when the answer holds rows and a `PartialError` (for
  example a query that exceeds the service's limits), the records are kept and
  the warning is shown with them.
- **Errors:** a KQL syntax error is reported with the service's own detail.
- **You provide:**
  - the workspace ID (fixed value `workspace`);
  - the time range (fixed value `timespan`, an ISO 8601 duration);
  - an app with the **Log Analytics Reader** role on the workspace. The token
    scope is `https://api.loganalytics.io/.default`.

**Microsoft Sentinel: incident and its alerts (Azure portal).**
- **Reads:** an incident opened in the Azure portal. Its address carries the
  incident's resource ID: subscription, resource group, workspace and
  incident.
- **Requests (Azure Resource Manager, `api-version=2025-09-01`):**
  1. `GET …/providers/Microsoft.SecurityInsights/incidents/<id>`, the incident,
     shown first as the case summary;
  2. `POST …/incidents/<id>/alerts`, its alerts.
- **You provide:**
  - `https://portal.azure.com` as the website;
  - an app with the **Microsoft Sentinel Reader** role. The token scope is
    `https://management.azure.com/.default`.
- **Check:** Microsoft is moving Microsoft Sentinel to the Defender portal. For
  workspaces already there, use the next template.

**Microsoft Defender portal: incident and its alerts (Microsoft Graph).**
- **Reads:** an incident opened in the Defender portal
  (`security.microsoft.com/incidents/<id>` or `…/incident2/<id>/overview`).
  This includes Microsoft Sentinel incidents once the workspace is connected
  to the portal.
- **Requests:**
  1. `GET https://graph.microsoft.com/v1.0/security/incidents/<id>`, the
     incident;
  2. the same request with `$expand=alerts`, its alerts with their evidence
     (devices, processes, users and so on).
- **You provide:**
  - `https://security.microsoft.com` as the website;
  - an app with the **SecurityIncident.Read.All** application permission. The
    token scope is `https://graph.microsoft.com/.default`.
- **Check:** Microsoft documents `$expand=alerts` on the incident list. Using it
  on a single incident follows the same OData convention, but has not been
  confirmed against a live tenant by the project.

### Elasticsearch, OpenSearch and Wazuh

Elasticsearch, OpenSearch and the Wazuh indexer share the same REST API. The
first two templates call the cluster directly, usually on port `9200`, not the
dashboard. Sign in with a username and password, or for Elasticsearch an
`Authorization: ApiKey <key>` header under **API key or access token**.

**Elasticsearch / OpenSearch / Wazuh indexer: search.**
- **Requests:** `POST /<index pattern>/_search`, with:
  - a query string (Lucene syntax) from the default search or the popup;
  - a time filter of the last 24 hours on `@timestamp`, the time field of
    Elastic Common Schema data and of Wazuh alerts;
  - newest records first.
- **Paging:** in pages of 100 with the `from` and `size` parameters. The total
  comes from `hits.total.value`.
- **Limit:** a search can page through at most 10,000 hits by default
  (`index.max_result_window`).
- **You provide:**
  - the index pattern (fixed value `index`; `wazuh-alerts-*` for Wazuh alerts,
    `.alerts-security.alerts-*` for Elastic Security alerts);
  - the time field (`time_field`) if your data uses another one;
  - the time range (`since`, date math such as `now-7d`).

**Elasticsearch / OpenSearch / Wazuh indexer: document from Discover.**
- **Reads:** a document opened from Discover in Kibana, OpenSearch Dashboards
  or the Wazuh dashboard. Its address names the index and document ID
  (`#/doc/<data view>/<index>?id=<id>`).
- **Requests:** `GET /<index>/_doc/<id>`.
- **Without a document link:** the Inspector panel's search is read.
- **Check:** the Inspector selectors are those of OpenSearch Dashboards and the
  Wazuh dashboard. Kibana's Inspect panel is similar but has not been tested.

**OpenSearch Dashboards / Wazuh dashboard: browser login.**
- **Use it when:** you can only reach the dashboard, not the cluster.
- **Reads:**
  - documents from their `#/doc/` links, through the search endpoint that
    Discover itself calls;
  - searches through the Inspector panel.
- **You provide:** nothing beyond your browser login.
- **Check:** that endpoint is internal to OpenSearch Dashboards rather than
  part of its public API, so a new version can change it.

### IBM QRadar

**IBM QRadar: offense and its events.**
- **Reads:** an offense, its events, and the Log Activity table where no
  offense is open.
- **Requests:**
  1. `GET /api/siem/offenses/<id>`, the case summary;
  2. an Ariel search job: `POST /api/ariel/searches`, then the status, then
     the results. The AQL query is limited to the offense's own time range.
- **You provide:** a browser login (the template repeats the `SEC` and
  `QRadarCSRF` cookies as headers) or an Authorized Service token.
- **Check:** adjust the `Version` header under *Extra request headers* to your
  API version.

### Other platforms

Any product with a page table, page JSON or a JSON API can be set up by hand
with the same steps; the templates above are examples of what the fields
mean.

## Limits

API reads support:
- JSON REST responses;
- the search-job protocol, with URL or form-body start parameters, the
  platform's failure reason and offset-paged results;
- offset and next-page-token pagination in URL parameters;
- browser-session, token, basic, OAuth 2.0 client credentials, named-cookie
  and anonymous sign-in.

Not included:
- interactive OAuth sign-in (authorization code or device code), and refresh
  tokens;
- XML, NDJSON streams, binary files and Link-header pagination;
- closed shadow roots and virtualized grids, which page readers cannot see
  into. *My own page script* remains available for unusual interfaces.

Up to 5,000 records are read per extraction, and link scanning is bounded, so
use a focused element on large case pages.

API references the templates follow:
- [Splunk REST search endpoints](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/9.4/search-endpoints/search-endpoint-descriptions)
- [Azure Monitor Logs query API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format)
- [Microsoft Sentinel incidents](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/get) and [their alerts](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts)
- [Microsoft Graph security incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents)
- [Microsoft identity platform client credentials](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Elasticsearch search](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search)
- [OpenSearch get document](https://docs.opensearch.org/latest/api-reference/document-apis/get-documents/)
- [Wazuh indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html)
- [IBM QRadar Ariel searches](https://ibmsecuritydocs.github.io/qradar_api_28.0/28.0--ariel-searches-POST.html)

## Troubleshooting: the check works but extraction returns 401 or 302

A successful **Test connection** only shows that the status address answers;
that address may not need permission to read records. With
**Sign-in → Use my current browser login**:

1. Open a SIEM record in the same browser profile and leave that tab open.
2. Keep the API address pointing at the SIEM (another website you read values
   from is only a source of request values, not the API).
3. Under **More options → Where API requests run**, choose **In the signed-in
   browser tab when possible**. Reads then run inside that tab, so the browser
   sends its own cookies (including HttpOnly and path-specific ones).
4. Click **Preview extraction**, save the connection if records appear, then
   use **Extract logs** on the page you extract from.

Token, password and named-cookie sign-in, a separate API origin, search jobs and
context requests always run through the local backend. VEILUX never retries a
failed sign-in through a different route. HTTP 403 can still return partial
results; 401 stops the extraction.
