<p align="center"><img alt="VEILUX logo" src="../extension/icons/logo.png" width="72"/></p>

# VEILUX: detailed diagrams

The [README](../README.md) keeps three overview diagrams. This page holds the detailed ones: every component, branch and time limit. Each section links back to the README section it expands.

- [1. Full data flow](#1-full-data-flow)
- [2. How Analyze, Ask and Report feed each other](#2-how-analyze-ask-and-report-feed-each-other)
- [3. A question, step by step](#3-a-question-step-by-step)
- [4. Full protection pipeline](#4-full-protection-pipeline)
- [5. Backend access check](#5-backend-access-check)
- [6. Connection editor flow](#6-connection-editor-flow)
- [7. Search-job sequence](#7-search-job-sequence)
- [8. Case lifecycle](#8-case-lifecycle)

## 1. Full data flow

Expands [How it works](../README.md#how-it-works). The extension is made of connections (the readers), the popup and a background worker; the backend checks the paired key, protects the case, sends only public indicators to threat intelligence and only placeholders to the AI provider, and restores the answer locally.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#E6F7FD","primaryBorderColor":"#0C7AA6","primaryTextColor":"#0F2233","lineColor":"#5B7A99","clusterBkg":"#F4F9FC","clusterBorder":"#9FC9DC","titleColor":"#0F2233","edgeLabelBackground":"#FFFFFF"},"flowchart":{"wrappingWidth":320}}}%%
flowchart TD
    SIEM[("🗄️ Your security tools<br/>SIEM pages · APIs<br/>search jobs")]
    subgraph EXT["🧩 Extension · popup + content scripts"]
        direction TB
        CON["Connections<br/>table · JSON · API<br/>Inspector · script"]
        POP["Popup<br/>Case · Options · Tools"]
        BG["Background<br/>worker + queue"]
    end
    subgraph BE["🛡️ Local backend · server.py, FastAPI · localhost:8000"]
        direction TB
        AUTH["Paired-key<br/>check"]
        PROT["Credential detection<br/>+ privacy masking"]
    end
    RES["🛡️ Local backend<br/>restores real values<br/>secrets stay masked"]
    AI{{"🤖 AI provider<br/>Groq · DeepSeek · Together<br/>OpenRouter · Gemini · Claude<br/>or your own model"}}
    TI{{"🔎 Threat intel<br/>VirusTotal · AbuseIPDB<br/>WHOIS / RDAP"}}
    OUT(["✅ Popup · Results<br/>with the real values"])

    SIEM -- "the open page, matched<br/>against your connections ·<br/>search jobs run<br/>through the backend" --> EXT
    CON --> POP --> BG
    BG -- "raw case" --> BE
    AUTH --> PROT
    PROT -- "public IOCs only" --> TI
    PROT -- "⟦USER#1⟧ ⟦IP#1⟧<br/>placeholders only" --> AI
    AI -- "answer with<br/>placeholders" --> RES
    RES --> OUT

    classDef local fill:#0B1220,stroke:#00C8F8,color:#F1F5F9,stroke-width:1.5px
    classDef ext fill:#E6F7FD,stroke:#0C7AA6,color:#0F2233
    classDef out fill:#FFF4E5,stroke:#E8920C,color:#3D2600,stroke-width:1.5px
    classDef ok fill:#ECFDF3,stroke:#16A34A,color:#0B3B1E,stroke-width:1.5px
    class AUTH,PROT,RES local
    class POP,BG,CON ext
    class AI,TI,SIEM out
    class OUT ok
```

## 2. How Analyze, Ask and Report feed each other

Expands [Analyze, Ask, Report](../README.md#analyze-ask-report-one-case-three-actions). All three actions go through the same protected request; its result is routed to the tab that matches its purpose.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#E6F7FD","primaryBorderColor":"#0C7AA6","primaryTextColor":"#0F2233","lineColor":"#5B7A99","clusterBkg":"#F4F9FC","clusterBorder":"#9FC9DC","titleColor":"#0F2233","edgeLabelBackground":"#FFFFFF"},"flowchart":{"wrappingWidth":320}}}%%
flowchart TD
    AN(["🔍 Analyze"]) --> CTX
    ASK(["💬 Ask"]) --> CTX
    REP(["✉️ Report"]) --> CTX
    CTX["🧠 Case context<br/>logs · statistics · case notes<br/>+ what this action adds"] --> REV["🔐 Credential review<br/>only values not decided<br/>for this case yet"]
    REV --> Q["⏳ Background queue<br/>one job per case<br/>3 cases at once by default"]
    Q --> BE["🛡️ Backend /analyze<br/>protect → TI* → AI → restore"]
    BE --> REC["🧾 Sent record"]
    REC --> R{"purpose"}
    R -- "analysis" --> OA["Analysis tab<br/>verdict + TI findings"]
    R -- "chat" --> OQ["Ask tab<br/>conversation"]
    R -- "report" --> OR["Report tab<br/>email from template"]

    classDef act fill:#0C7AA6,stroke:#00C8F8,color:#FFFFFF,stroke-width:2px
    classDef pipe fill:#0B1220,stroke:#00C8F8,color:#F1F5F9
    classDef outp fill:#ECFDF3,stroke:#16A34A,color:#0B3B1E
    classDef dec fill:#E6F7FD,stroke:#0C7AA6,color:#0F2233
    class AN,ASK,REP act
    class CTX,REV,Q,BE,REC pipe
    class OA,OQ,OR outp
    class R dec
```

<sub>\* Threat-intelligence lookups run for **Analyze** only; Ask and Report reuse the results already in the case.</sub>

What each action writes, and what the others read from it:

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#E6F7FD","primaryBorderColor":"#0C7AA6","primaryTextColor":"#0F2233","lineColor":"#5B7A99","clusterBkg":"#F4F9FC","clusterBorder":"#9FC9DC","titleColor":"#0F2233","edgeLabelBackground":"#FFFFFF"},"flowchart":{"wrappingWidth":320}}}%%
flowchart TD
    AN(["🔍 Analyze"]) -- "writes" --> A["Analysis +<br/>TI findings"]
    A -- "context" --> ASK(["💬 Ask"])
    A -- "background only" --> REP(["✉️ Report"])
    ASK -- "writes" --> C["Conversation<br/>last 8 exchanges"]
    C -- "Add to case notes" --> N["📝 Case notes"]
    N -- "sent with" --> AN
    N -- "sent with" --> ASK
    N -- "stated as findings" --> REP
    N -. "case changed" .-> S["⚠️ Analysis out of date<br/>Re-analyze"]
    S -.-> AN

    classDef act fill:#0C7AA6,stroke:#00C8F8,color:#FFFFFF,stroke-width:2px
    classDef data fill:#E6F7FD,stroke:#0C7AA6,color:#0F2233
    classDef warn fill:#FFF4E5,stroke:#E8920C,color:#3D2600
    class AN,ASK,REP act
    class A,C,N data
    class S warn
```

## 3. A question, step by step

What happens between typing a question in the **Ask** tab and reading the answer with the real values.

```mermaid
%%{init: {"theme":"base","themeVariables":{"actorBkg":"#0B1220","actorTextColor":"#F1F5F9","actorBorder":"#00C8F8","actorLineColor":"#9FC9DC","signalColor":"#5B7A99","signalTextColor":"#5B7A99","noteBkgColor":"#FFF4E5","noteBorderColor":"#E8920C","noteTextColor":"#3D2600","labelBoxBkgColor":"#E6F7FD","labelBoxBorderColor":"#0C7AA6","labelTextColor":"#0F2233","loopTextColor":"#5B7A99","sequenceNumberColor":"#FFFFFF"},"sequence":{"diagramMarginY":80,"mirrorActors":false}}}%%
sequenceDiagram
    %% The top margin and the single row of participants keep them clear of GitHub's diagram buttons.
    autonumber
    participant A as 🕵️ Analyst
    participant P as Popup · Ask tab
    participant W as Background worker
    participant B as Local backend
    participant M as AI model

    A->>P: "Was j.doe seen<br/>on other hosts?"
    Note over P: Build context:<br/>earlier analysis<br/>TI already gathered<br/>last 8 exchanges<br/>case notes · the question
    P->>B: /secrets/scan (preflight)
    B-->>P: uncertain values not yet<br/>decided for this case
    opt something new to decide
        P->>A: Review stage: Keep or Hide
        A-->>P: Continue safely
    end
    P->>W: START_ANALYSIS<br/>(purpose: chat)
    W->>B: POST /analyze<br/>(whole case, TI lookups off)
    Note over B: credential masking<br/>→ privacy masking<br/>→ final boundary check
    B->>M: prompt with ⟦USER#35;1⟧<br/>⟦IP_EXT#35;1⟧ only
    M-->>B: answer with<br/>placeholders
    Note over B: restore privacy values<br/>(secrets stay ⟦SECRET#35;n⟧)
    B-->>W: answer + what was sent
    Note over W: Sent record<br/>pendingAnswer<br/>for this case
    W-->>P: answer (even if the popup<br/>was closed meanwhile)
    P-->>A: Answer with real values
    A->>P: Add to case notes
    Note over P: From now on Analyze,<br/>Ask and Report all<br/>receive this note
```

- **One job per case, several cases at once.** Closing the popup does not cancel the request; the answer is shown the next time the case is opened.
- **Review once per case.** The preflight (`/secrets/scan`) only shows values not yet decided for this case.
- **Every action is recorded** in the **Sent** tab with its purpose: Analysis, Ask or Email report.

## 4. Full protection pipeline

Expands [Sanitization controls and review](../README.md#sanitization-controls-and-review), including the threat-intelligence branch and the time limits.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#E6F7FD","primaryBorderColor":"#0C7AA6","primaryTextColor":"#0F2233","lineColor":"#5B7A99","clusterBkg":"#F4F9FC","clusterBorder":"#9FC9DC","titleColor":"#0F2233","edgeLabelBackground":"#FFFFFF"},"flowchart":{"wrappingWidth":320}}}%%
flowchart TD
    %% The arrow ends at the group, so it does not cross the group's title.
    IN(["Logs · case notes · statistics<br/>prompt · approved lessons"]) --> LOCAL
    subgraph LOCAL["🛡️ Runs on your computer"]
        SEC["① Credential detection<br/>10 mechanisms, one switch"] --> SPLIT(["What kind of finding?"])
        SPLIT -- "high confidence" --> MASK1["Masked automatically<br/>→ ⟦SECRET#n⟧"]
        SPLIT -- "uncertain: user:password,<br/>GUID/hash shapes" --> REV["Review stage<br/>Keep ✓ by default · Hide"]
        MASK1 --> PRIV
        REV --> PRIV["② Privacy masking<br/>IPs · users · hosts · domains · emails<br/>keywords · JSON keys · custom rules"]
        PRIV --> TIQ(["Threat intel switched on?<br/>Analyze only"])
        TIQ -- "yes · public IOCs,<br/>credentials blocked" --> LOOK["Lookups · 45 s budget · cached<br/>results protected too"]
        TIQ -- "no" --> FIN
        LOOK --> FIN["③ Final boundary check<br/>on the assembled prompt · fails closed"]
    end
    FIN -- "placeholders only" --> AI{{"🤖 AI provider · 180 s cap"}}
    AI --> RESTORE["④ Restore privacy values locally<br/>secrets stay ⟦SECRET#n⟧"]
    RESTORE --> OUT(["Analysis · Answer · Report"])

    classDef safe fill:#0B1220,stroke:#00C8F8,color:#F1F5F9
    classDef ext fill:#FFF4E5,stroke:#E8920C,color:#3D2600
    classDef ok fill:#ECFDF3,stroke:#16A34A,color:#0B3B1E
    classDef q fill:#E6F7FD,stroke:#0C7AA6,color:#0F2233
    class SEC,REV,MASK1,PRIV,LOOK,FIN safe
    class SPLIT,TIQ q
    class AI ext
    class RESTORE,OUT,IN ok
```

## 5. Backend access check

Expands [Pair the extension with the backend](../README.md#3-pair-the-extension-with-the-backend). Every incoming request passes these checks in order.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#E6F7FD","primaryBorderColor":"#0C7AA6","primaryTextColor":"#0F2233","lineColor":"#5B7A99","clusterBkg":"#F4F9FC","clusterBorder":"#9FC9DC","titleColor":"#0F2233","edgeLabelBackground":"#FFFFFF"},"flowchart":{"wrappingWidth":320}}}%%
flowchart TD
    R["Incoming request"] --> O{"Origin is an<br/>extension?"}
    O -- "web page" --> X1["403 refused"]
    O -- "chrome-extension://<br/>moz-extension://<br/>safari-web-extension://<br/>or no Origin (your scripts)" --> H{"Host is localhost,<br/>127.0.0.1, [::1]<br/>or allowed?"}
    H -- "no · DNS rebinding" --> X2["403 refused"]
    H -- "yes" --> P{"GET /health<br/>or POST /pair?"}
    P -- "yes" --> OK["✅ answered"]
    P -- "no" --> T{"X-Veilux-Token<br/>matches the key?"}
    T -- "no" --> X3["401 pairing_required"]
    T -- "yes" --> OK
    classDef bad fill:#FDECEC,stroke:#DC2626,color:#5B0B0B
    classDef good fill:#ECFDF3,stroke:#16A34A,color:#0B3B1E
    class X1,X2,X3 bad
    class OK good
```

See [SECURITY.md](../SECURITY.md) for the key file's permissions, pairing limits and network use.

## 6. Connection editor flow

Expands [Configure your connections](../README.md#5-configure-your-connections). Steps 3 to 5 appear only for API connections. The [connection setup guide](CONNECTOR_SETUP.md) covers every field.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#E6F7FD","primaryBorderColor":"#0C7AA6","primaryTextColor":"#0F2233","lineColor":"#5B7A99","clusterBkg":"#F4F9FC","clusterBorder":"#9FC9DC","titleColor":"#0F2233","edgeLabelBackground":"#FFFFFF"},"flowchart":{"wrappingWidth":320}}}%%
flowchart TD
    S1["1️⃣ Basics<br/>template · name · website"] --> S2{"2️⃣ Where are the logs?"}
    S2 -- "table on the page<br/>JSON on the page<br/>Inspector panel<br/>your page script" --> PV
    S2 -- "an API request" --> S3["3️⃣ API request<br/>path · params · body · ${name}<br/>records path · search jobs"]
    S3 --> S4["4️⃣ Request values<br/>page address · links on a page<br/>text · attribute · fixed value"]
    S4 --> S5["5️⃣ Sign-in<br/>browser login · key/token<br/>app sign-in (OAuth 2.0)<br/>user+password · cookie · none"]
    S5 --> PV["👁️ Preview extraction"]
    PV --> SV(["💾 Save connection"])
    classDef step fill:#E6F7FD,stroke:#0C7AA6,color:#0F2233
    classDef done fill:#0C7AA6,stroke:#00C8F8,color:#FFFFFF
    class S1,S2,S3,S4,S5,PV step
    class SV done
```

## 7. Search-job sequence

The [search-job example](../README.md#example-an-api-with-search-jobs) for a fictional SIEM at `https://siem.example.com`. Search jobs always run through the local backend.

```mermaid
%%{init: {"theme":"base","themeVariables":{"actorBkg":"#0B1220","actorTextColor":"#F1F5F9","actorBorder":"#00C8F8","actorLineColor":"#9FC9DC","signalColor":"#5B7A99","signalTextColor":"#5B7A99","noteBkgColor":"#FFF4E5","noteBorderColor":"#E8920C","noteTextColor":"#3D2600","labelBoxBkgColor":"#E6F7FD","labelBoxBorderColor":"#0C7AA6","labelTextColor":"#0F2233","loopTextColor":"#5B7A99","sequenceNumberColor":"#FFFFFF"},"sequence":{"diagramMarginY":80,"mirrorActors":false}}}%%
sequenceDiagram
    %% The top margin and the single row of participants keep them clear of GitHub's diagram buttons.
    autonumber
    participant X as Extension
    participant B as Local backend
    participant S as siem.example.com
    participant T as Token address
    X->>B: POST /fetch-siem-logs<br/>(fetch_mode: search_job)
    opt app sign-in<br/>(OAuth 2.0 client credentials)
        B->>T: client ID · client secret · scope
        T-->>B: access token, kept in<br/>memory until it expires
    end
    opt context request
        B->>S: GET the record the search is about
        S-->>B: record (e.g. its time range)
    end
    B->>S: POST /api/searches<br/>(URL parameters or a form body)
    S-->>B: { job_id }
    loop until finished, failed<br/>(the platform's reason is shown)<br/>or timed out
        B->>S: GET /api/searches/${job_id}
        S-->>B: status
    end
    B->>S: GET /api/searches/${job_id}/results<br/>(page by page with offset paging)
    S-->>B: records
    B-->>X: logs → the case that<br/>started the extraction
```

## 8. Case lifecycle

Expands [Cases](../README.md#cases): how a case moves between open, queued, running, new results and archived.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#E6F7FD","primaryBorderColor":"#0C7AA6","primaryTextColor":"#0F2233","lineColor":"#5B7A99","clusterBkg":"#F4F9FC","clusterBorder":"#9FC9DC","titleColor":"#0F2233","edgeLabelBackground":"#FFFFFF"}}}%%
stateDiagram-v2
    direction TB
    [*] --> Open: new or freed slot
    Open --> Queued: Analyze · Ask · Report<br/>(limit reached)
    Open --> Running: Analyze · Ask · Report
    Queued --> Running: a slot frees up
    Running --> NewResults: finished, even with<br/>the popup closed
    NewResults --> Open: you open the case
    Open --> Archived: ⋯ → Archive
    Archived --> Open: Restore
    Archived --> [*]: Delete · Clear archive
```
