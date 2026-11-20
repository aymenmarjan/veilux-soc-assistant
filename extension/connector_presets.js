// Platform templates for the connection editor. Each one is a partial saved
// connection: applying it fills the form exactly as opening a saved connection
// would. Saved connections are never overwritten on extension upgrades.
// Every template follows the vendor's public API reference; versions and
// permissions differ between deployments, so each value stays editable.
const ELASTIC_SEARCH_BODY = JSON.stringify({
  query: { bool: { filter: [{ range: { '${time_field}': { gte: '${since}' } } }], must: [{ query_string: { query: '${query}' } }] } },
  sort: [{ '${time_field}': { order: 'desc' } }],
  track_total_hits: true
});
const SENTINEL_INCIDENT = '/subscriptions/${subscription}/resourceGroups/${resource_group}/providers/Microsoft.OperationalInsights'
  + '/workspaces/${workspace}/providers/Microsoft.SecurityInsights/incidents/${incident_id}';
const CONNECTOR_PRESETS = {
  splunk_results: {
    // Splunk Web shows the ID of the search being viewed in the address
    // (...?sid=<search ID>). Its results are read from the REST API on the
    // management port, page by page (offset and count):
    //   GET /services/search/v2/jobs/<sid>/results?output_mode=json -> {"results": [...]}
    // (the v2 results endpoint of Splunk Enterprise 9.0.1 and later, which
    // replaces the deprecated v1 one; older versions use /services/search/jobs/...)
    // The token must belong to the user who ran the search, or to a user
    // allowed to read it. Search results expire (ten minutes by default for
    // an ad hoc search); then run the search again.
    discoverPathHint: 'app/search',
    statistics: { mode: 'records' },
    auth: { type: 'header', headerName: 'Authorization', cookieName: '' },
    api: {
      enabled: true,
      linkRegex: '[?&]sid=(?<sid>[^&#]+)',
      method: 'GET', pathTemplate: '/services/search/v2/jobs/${sid}/results',
      queryTemplate: { output_mode: 'json' },
      headersTemplate: { 'Accept': 'application/json' }, bodyTemplate: '',
      responsePath: 'results',
      pagination: { mode: 'offset', parameter: 'offset', sizeParameter: 'count', pageSize: 100, maxPages: 50 },
      testPath: '/services/server/info?output_mode=json',
      fetchMode: 'single_request', job: {}, context: {}
    },
    // Without a search ID in the address, the results table on screen is read.
    dom: { discover: { strategy: 'table_scrape', tableSelector: '' } }
  },
  splunk: {
    // Splunk search jobs use the same create -> poll -> results engine as
    // any other search-job API; only the paths and field names differ.
    //   create : POST /services/search/jobs (form body: search, output_mode,
    //            earliest_time, latest_time) -> {"sid": ...}
    //   poll   : GET  /services/search/jobs/${job_id}?output_mode=json
    //            -> entry[0].content.dispatchState (DONE / FAILED), with the
    //            reasons for a failure in entry[0].content.messages
    //   results: GET  /services/search/v2/jobs/${job_id}/results?output_mode=json
    //            -> {"results": [...]}, read page by page (offset and count);
    //            v2 is the results endpoint since Splunk 9.0.1 (v1 is deprecated)
    // The API lives on the management port (8089 by default), while the web
    // UI is usually on 8000: the API address should be the 8089 one. Host
    // matching uses the hostname only, so the UI tabs still match.
    discoverPathHint: 'app/search',
    statistics: { mode: 'records' },
    auth: { type: 'header', headerName: 'Authorization', cookieName: '' },
    api: {
      enabled: true,
      // Searches are started from the default search (SPL) or a search typed
      // in the popup; no value is read from the page.
      linkRegex: '',
      contentRegex: '',
      method: 'GET',
      pathTemplate: '',
      headersTemplate: { 'Accept': 'application/json' },
      bodyTemplate: '',
      responsePath: 'results',
      testPath: '/services/server/info?output_mode=json',
      fetchMode: 'search_job',
      defaultQuery: 'search index=* | head 100',
      pagination: { mode: 'offset', parameter: 'offset', sizeParameter: 'count', pageSize: 100, maxPages: 10 },
      job: {
        createMethod: 'POST',
        createPathTemplate: '/services/search/jobs',
        // SPL needs the "search" command first unless the query starts with
        // another generating command (such as | tstats); it is part of the
        // default search rather than forced on every query.
        createQueryTemplate: { 'search': '${query}', 'output_mode': 'json', 'earliest_time': '-24h', 'latest_time': 'now' },
        createParametersAs: 'form',
        createBodyTemplate: '',
        queryParameter: 'search',
        jobIdPath: 'sid',
        statusPathTemplate: '/services/search/jobs/${job_id}?output_mode=json',
        statusField: 'entry.0.content.dispatchState',
        completeValues: 'DONE',
        errorValues: 'FAILED',
        errorMessagePath: 'entry.0.content.messages',
        resultsPathTemplate: '/services/search/v2/jobs/${job_id}/results?output_mode=json',
        pollIntervalSeconds: 2,
        timeoutSeconds: 120
      },
      context: {}
    },
    dom: { discover: { strategy: 'table_scrape', tableSelector: '' } }
  },
  sentinel_incident: {
    // A Microsoft Sentinel incident opened in the Azure portal. Its address
    // carries the incident's resource ID, which names the subscription,
    // resource group, workspace and incident. Azure Resource Manager returns
    // the incident (read first, as the case summary) and its alerts:
    //   GET  .../providers/Microsoft.SecurityInsights/incidents/<id>?api-version=...
    //   POST .../providers/Microsoft.SecurityInsights/incidents/<id>/alerts?api-version=... -> {"value": [...]}
    // The app needs the Microsoft Sentinel Reader role on the workspace.
    siemBaseUrl: 'https://management.azure.com',
    statistics: { mode: 'records' },
    auth: { type: 'oauth_client_credentials', headerName: 'Authorization', cookieName: '',
      tokenUrl: 'https://login.microsoftonline.com/YOUR-TENANT-ID/oauth2/v2.0/token', scope: 'https://management.azure.com/.default' },
    api: {
      enabled: true,
      linkRegex: '/subscriptions/(?<subscription>[0-9A-Fa-f-]{36})/resource[Gg]roups/(?<resource_group>[^/?#]+)/providers/Microsoft\\.OperationalInsights/workspaces/(?<workspace>[^/?#]+)/providers/Microsoft\\.SecurityInsights/[Ii]ncidents/(?<incident_id>[^/?#]+)',
      method: 'POST', pathTemplate: SENTINEL_INCIDENT + '/alerts',
      queryTemplate: { 'api-version': '2025-09-01' },
      headersTemplate: { 'Accept': 'application/json' }, bodyTemplate: '',
      responsePath: 'value', testPath: '',
      fetchMode: 'single_request', job: {},
      context: { method: 'GET', pathTemplate: SENTINEL_INCIDENT + '?api-version=2025-09-01', responsePath: '' }
    },
    dom: { discover: { strategy: 'api_request' } }
  },
  sentinel: {
    // Azure Monitor Logs query API: a KQL query against one workspace. Column
    // names and rows are returned separately (tables.0.columns, tables.0.rows).
    // An answer can hold rows and a "PartialError" at once; VEILUX reports it.
    // The app needs the Log Analytics Reader role on the workspace.
    siemBaseUrl: 'https://api.loganalytics.azure.com',
    statistics: { mode: 'records' },
    auth: { type: 'oauth_client_credentials', headerName: 'Authorization', cookieName: '',
      tokenUrl: 'https://login.microsoftonline.com/YOUR-TENANT-ID/oauth2/v2.0/token', scope: 'https://api.loganalytics.io/.default' },
    api: {
      enabled: true, method: 'POST', pathTemplate: '/v1/workspaces/${workspace}/query',
      headersTemplate: { 'Accept': 'application/json' }, bodyTemplate: '{"query":"${query}","timespan":"${timespan}"}',
      responsePath: 'tables.0.rows', recordFormat: 'columns', columnsPath: 'tables.0.columns',
      parameters: { workspace: 'YOUR-WORKSPACE-ID', timespan: 'P1D' }, defaultQuery: 'SecurityAlert | sort by TimeGenerated desc | take 100',
      fetchMode: 'single_request', testPath: '', job: {}, context: {}
    },
    dom: { discover: { strategy: 'api_request' } }
  },
  defender_incident: {
    // An incident in the Microsoft Defender portal, which also shows
    // Microsoft Sentinel incidents once the workspace is connected to it.
    // Microsoft Graph returns the incident (read first, as the case summary)
    // and, expanded, its alerts with their evidence:
    //   GET /v1.0/security/incidents/<id>?$expand=alerts -> {"alerts": [...]}
    // The app needs the SecurityIncident.Read.All application permission.
    siemBaseUrl: 'https://graph.microsoft.com',
    statistics: { mode: 'records' },
    auth: { type: 'oauth_client_credentials', headerName: 'Authorization', cookieName: '',
      tokenUrl: 'https://login.microsoftonline.com/YOUR-TENANT-ID/oauth2/v2.0/token', scope: 'https://graph.microsoft.com/.default' },
    api: {
      enabled: true,
      linkRegex: '/(?:incidents|incident2)/(?<incident_id>\\d+)',
      method: 'GET', pathTemplate: '/v1.0/security/incidents/${incident_id}',
      queryTemplate: { '$expand': 'alerts' },
      headersTemplate: { 'Accept': 'application/json' }, bodyTemplate: '',
      responsePath: 'alerts', testPath: '/v1.0/security/incidents?$top=1',
      fetchMode: 'single_request', job: {},
      context: { method: 'GET', pathTemplate: '/v1.0/security/incidents/${incident_id}', responsePath: '' }
    },
    dom: { discover: { strategy: 'api_request' } }
  },
  elastic_search: {
    // Elasticsearch, OpenSearch and the Wazuh indexer share the search API:
    //   POST /<index pattern>/_search -> hits.hits, total in hits.total.value
    // read page by page with the from and size URL parameters (up to 10,000
    // records, the default index.max_result_window). The default search is a
    // query string (Lucene syntax), limited to the last 24 hours of
    // @timestamp, the time field of Elastic Common Schema data and of Wazuh
    // alerts (index pattern wazuh-alerts-*), as Wazuh's own examples query it.
    statistics: { mode: 'records' },
    auth: { type: 'basic', headerName: 'Authorization', cookieName: '' },
    api: {
      enabled: true, method: 'POST', pathTemplate: '/${index}/_search',
      headersTemplate: { 'Accept': 'application/json' }, bodyTemplate: ELASTIC_SEARCH_BODY,
      responsePath: 'hits.hits', totalPath: 'hits.total.value',
      parameters: { index: 'logs-*', time_field: '@timestamp', since: 'now-24h' }, defaultQuery: '*',
      pagination: { mode: 'offset', parameter: 'from', sizeParameter: 'size', pageSize: 100, maxPages: 10 },
      fetchMode: 'single_request', testPath: '/', job: {}, context: {}
    },
    dom: { discover: { strategy: 'api_request' } }
  },
  elastic_document: {
    // A document opened from Discover (Kibana, OpenSearch Dashboards or the
    // Wazuh dashboard): its address names the index and document ID
    // (#/doc/<data view>/<index>?id=<id>), and the document API returns it:
    //   GET /<index>/_doc/<id> -> {"_index": ..., "_id": ..., "_source": {...}}
    // The API address is the cluster itself (often port 9200), not the
    // dashboard. Without a document link, the Inspector panel's search is read.
    discoverPathHint: VeiluxConnectors.opensearch.discoverPathHint,
    statistics: { mode: 'records' },
    auth: { type: 'basic', headerName: 'Authorization', cookieName: '' },
    api: {
      enabled: true,
      linkRegex: VeiluxConnectors.opensearch.linkRegex,
      method: 'GET', pathTemplate: '/${index}/_doc/${doc_id}',
      headersTemplate: { 'Accept': 'application/json' }, bodyTemplate: '',
      responsePath: '', testPath: '/',
      fetchMode: 'single_request', job: {}, context: {}
    },
    dom: { discover: { strategy: 'inspector_panel', ...VeiluxConnectors.opensearch.inspector } }
  },
  opensearch: {
    // OpenSearch Dashboards or the Wazuh dashboard, with the browser login:
    // document links (#/doc/<index-pattern>/<index>?id=<id>) are read through
    // the search endpoint Discover itself calls (internal to Dashboards, so it
    // can change between versions), and searches through the Inspector panel.
    // With direct access to the cluster, the elastic_document template uses
    // the public document API instead. Every value is written out below.
    discoverPathHint: VeiluxConnectors.opensearch.discoverPathHint,
    // Sign-in can span several cookies, so the whole browser session is used.
    auth: { type: 'browser_session', headersFromCookies: {} },
    statistics: { mode: 'opensearch' },
    api: {
      enabled: true,
      linkRegex: VeiluxConnectors.opensearch.linkRegex,
      method: VeiluxConnectors.opensearch.method, pathTemplate: VeiluxConnectors.opensearch.pathTemplate,
      headersTemplate: { ...VeiluxConnectors.opensearch.headersTemplate },
      bodyTemplate: VeiluxConnectors.opensearch.bodyTemplate,
      responsePath: VeiluxConnectors.opensearch.responsePath, testPath: VeiluxConnectors.opensearch.testPath,
      fetchMode: 'single_request',
      job: {}, context: {}
    },
    dom: { discover: { strategy: 'inspector_panel', ...VeiluxConnectors.opensearch.inspector } }
  },
  qradar: {
    // IBM QRadar: an offense is read through the offenses API, and its events
    // through the Ariel search API, which runs searches as asynchronous jobs
    // (create -> poll -> results), so this template uses search_job mode
    // through the local backend.
    // Sign-in uses the browser session: the QRadar API accepts the console's
    // SEC session cookie when the SEC and QRadarCSRF cookie values are also
    // sent as headers. An Authorized Service token works too: choose
    // "API key or access token" and paste it.
    // The Version 12.0 header is a starting value: check it against the API
    // documentation of the installed version.
    discoverPathHint: 'arielSearch',
    statistics: { mode: 'records' },
    auth: {
      type: 'browser_session',
      headersFromCookies: { 'SEC': 'SEC', 'QRadarCSRF': 'QRadarCSRF' },
      headerName: 'SEC', cookieName: ''
    },
    api: {
      enabled: true,
      // Matches the offense summary address of the classic console
      // (...summaryId=42) and /offenses/42 links of the newer interface.
      linkRegex: '(?:offensesummary[^#\\s"\']*[?&]summaryId=|/offenses/)(?<offense_id>\\d+)',
      // Where the address carries no ID, the offense number shown in the page
      // title is used instead.
      contentRegex: 'Offense\\s+(?<offense_id>\\d+)\\s*\\(Summary\\)',
      method: 'GET',
      pathTemplate: '/api/siem/offenses/${offense_id}',
      headersTemplate: { 'Version': '12.0', 'Accept': 'application/json' },
      bodyTemplate: '',
      responsePath: 'events',
      // The connection check queries the offenses API with a filter that
      // matches nothing, so it passes only when the sign-in may read offenses.
      testPath: '/api/siem/offenses?fields=id&filter=id%3D0',
      fetchMode: 'search_job',
      job: {
        createMethod: 'POST',
        createPathTemplate: '/api/ariel/searches',
        // AQL that returns readable names (QIDNAME and similar) and the raw
        // event (UTF8(payload)) rather than numeric IDs only. The search is
        // limited to the offense's own time range, read from the context
        // request (${context.start_time} to ${context.last_updated_time},
        // padded by 10 minutes), which keeps it short.
        createQueryTemplate: { 'query_expression': "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, QIDNAME(qid) AS event_name, LOGSOURCENAME(logsourceid) AS log_source, CATEGORYNAME(category) AS category, sourceip, sourceport, destinationip, destinationport, PROTOCOLNAME(protocolid) AS protocol, username, UTF8(payload) AS payload FROM events WHERE INOFFENSE(${offense_id}) ORDER BY starttime DESC LIMIT 50 START ${context.start_time-600000} STOP ${context.last_updated_time+600000}" },
        createBodyTemplate: '',
        queryParameter: 'query_expression',
        jobIdPath: 'search_id',
        statusPathTemplate: '/api/ariel/searches/${job_id}',
        statusField: 'status',
        completeValues: 'COMPLETED',
        errorValues: 'ERROR, CANCELED',
        resultsPathTemplate: '/api/ariel/searches/${job_id}/results',
        pollIntervalSeconds: 2,
        timeoutSeconds: 90
      },
      context: {
        method: 'GET',
        pathTemplate: '/api/siem/offenses/${offense_id}',
        responsePath: ''
      }
    },
    dom: { discover: { strategy: 'table_scrape', tableSelector: '' } }
  }
};

const CONNECTOR_PRESET_NOTES = {
  splunk_results: 'Reads the results of the search you are viewing (the sid in its address) from the REST API. Use the console as the website and the management port (usually 8089) as the API address, with a token ("Bearer <token>") of the user who ran the search.',
  splunk: 'Runs the default search (SPL) or a search typed in the popup as a search job, over the last 24 hours. Use the management port (usually 8089) as the API address and a token ("Bearer <token>") or a username and password.',
  sentinel_incident: 'Reads an incident opened in the Azure portal, then its alerts, through Azure Resource Manager. Use https://portal.azure.com as the website, and an app registration with the Microsoft Sentinel Reader role: replace YOUR-TENANT-ID and enter its client ID and secret.',
  sentinel: 'Runs a KQL query in one Log Analytics workspace. Replace YOUR-WORKSPACE-ID and YOUR-TENANT-ID, and use an app registration with the Log Analytics Reader role, or choose "API key or access token" and paste a current Bearer token.',
  defender_incident: 'Reads an incident opened in the Microsoft Defender portal and its alerts through Microsoft Graph. Use https://security.microsoft.com as the website, and an app registration with the SecurityIncident.Read.All permission: replace YOUR-TENANT-ID and enter its client ID and secret.',
  elastic_search: 'Searches an Elasticsearch, OpenSearch or Wazuh indexer cluster over the last 24 hours. Set the index pattern under Request values, such as wazuh-alerts-* for Wazuh alerts, and the time field if your data does not use @timestamp. The API address is the cluster, often port 9200.',
  elastic_document: 'Reads a document opened from Discover (Kibana, OpenSearch Dashboards or the Wazuh dashboard) through the cluster\'s document API; otherwise the Inspector panel\'s search. The API address is the cluster, often port 9200, not the dashboard.',
  opensearch: 'Uses your browser login to OpenSearch Dashboards or the Wazuh dashboard: documents from their #/doc/ links, and Discover searches through the Inspector panel. No cluster credentials are needed.',
  qradar: 'Reads an offense and its events through the Ariel search API, and the Log Activity table otherwise. Check the Version header against your QRadar API documentation.'
};
