"""Local, deterministic credential detection for SOC log text.

Provider prefixes are an offline, reviewed subset of Gitleaks 8.24.2 and
Secretlint 9.3.4.  See docs/SECRET_RULE_CATALOG.md for provenance and scope.
"""

from dataclasses import dataclass, asdict, replace
import re
import json
import math
import base64
import bisect
from collections import Counter
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
import time
import regex as bounded_regex
from typing import Iterable, List, Sequence


_WORK = ContextVar("secret_scan_work", default=None)


def check_work():
    state = _WORK.get()
    if state and (state["cancel"].is_set() or time.monotonic() >= state["deadline"]):
        raise TimeoutError("sanitization work budget exhausted")


@contextmanager
def scanning_work(cancel_event, deadline):
    """Bounded parse cache and cancellation state, scoped to one worker call."""
    token = _WORK.set({"cancel": cancel_event, "deadline": deadline, "records": OrderedDict()})
    try:
        check_work()
        yield
        check_work()
    finally:
        _WORK.reset(token)


@dataclass(frozen=True)
class SecretFinding:
    start: int
    end: int
    value: str
    kind: str
    reason: str
    confidence: str = "high"
    scalar_kind: str | None = None
    source_path: tuple = ()

    def public(self) -> dict:
        return asdict(self)


# Keep these prefix/shape based.  A random long word is not evidence.
PROVIDER_RULES: Sequence[tuple[str, re.Pattern, str]] = (
    (
        "AWS access key",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        "AWS access-key prefix",
    ),
    ("GitLab token", re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"), "GitLab personal-access-token prefix"),
    ("Azure DevOps token", re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{75}AZDO[A-Za-z0-9]{5}(?![A-Za-z0-9])"), "Azure DevOps PAT signature"),
    ("PyPI token", re.compile(r"(?<![A-Za-z0-9_-])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])"), "PyPI API-token prefix"),
    ("npm token", re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"), "npm access-token prefix"),
    ("SendGrid token", re.compile(r"(?<![A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,128}(?![A-Za-z0-9_-])"), "SendGrid API-key structure"),
    ("Twilio key", re.compile(r"(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![A-Za-z0-9])"), "Twilio secret-key prefix"),
    ("Mailgun key", re.compile(r"(?<![A-Za-z0-9-])key-[0-9a-zA-Z]{32}(?![A-Za-z0-9])"), "Mailgun API-key prefix"),
    ("DigitalOcean token", re.compile(r"(?<![A-Za-z0-9_])dop_v1_[A-Fa-f0-9]{64}(?![A-Za-z0-9])"), "DigitalOcean token prefix"),
    ("DigitalOcean OAuth token", re.compile(r"(?<![A-Za-z0-9_])doo_v1_[a-f0-9]{64}(?![A-Za-z0-9])"), "DigitalOcean OAuth access-token prefix"),
    ("DigitalOcean refresh token", re.compile(r"(?<![A-Za-z0-9_])dor_v1_[a-f0-9]{64}(?![A-Za-z0-9])", re.I), "DigitalOcean OAuth refresh-token prefix"),
    ("Shopify token", re.compile(r"(?<![A-Za-z0-9_])shp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}(?![A-Za-z0-9])"), "Shopify token prefix"),
    ("Square token", re.compile(r"(?<![A-Za-z0-9_-])EAAA[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), "Square access-token prefix"),
    ("Telegram bot token", re.compile(r"(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"), "Telegram bot-token shape"),
    ("Discord token", re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}(?![A-Za-z0-9_-])"), "Discord token structure"),
    ("OpenAI key", re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), "OpenAI secret-key prefix"),
    ("Anthropic key", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), "Anthropic secret-key prefix"),
    ("Hugging Face token", re.compile(r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,}(?![A-Za-z0-9])"), "Hugging Face token prefix"),
    ("Postman key", re.compile(r"(?<![A-Za-z0-9-])PMAK-[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])"), "Postman API-key prefix"),
    ("Vault token", re.compile(r"(?<![A-Za-z0-9_.-])hvs\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), "Hashicorp Vault token prefix"),
    ("Age secret key", re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{50,70}"), "age private-key prefix"),
    ("Clojars token", re.compile(r"(?<![A-Za-z0-9_])CLOJARS_[A-Za-z0-9]{60}(?![A-Za-z0-9])"), "Clojars API-token prefix"),
    ("Cloudflare Origin CA key", re.compile(r"(?<![A-Za-z0-9.])v1\.0-[a-f0-9]{24}-[a-f0-9]{146}(?![A-Za-z0-9])", re.I), "Cloudflare Origin CA key structure"),
    ("Databricks token", re.compile(r"(?<![A-Za-z0-9])dapi[a-f0-9]{32}(?:-\d)?(?![A-Za-z0-9])", re.I), "Databricks API-token prefix"),
    ("Doppler token", re.compile(r"(?<![A-Za-z0-9.])dp\.pt\.[A-Za-z0-9]{43}(?![A-Za-z0-9])"), "Doppler API-token prefix"),
    ("Grafana cloud token", re.compile(r"(?<![A-Za-z0-9_])glc_[A-Za-z0-9+/]{32,400}={0,3}(?![A-Za-z0-9+/=])", re.I), "Grafana cloud-token prefix"),
    ("Grafana service account token", re.compile(r"(?<![A-Za-z0-9_])glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}(?![A-Za-z0-9])"), "Grafana service-account-token structure"),
    ("Harness token", re.compile(r"(?<![A-Za-z0-9_.-])(?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20}(?![A-Za-z0-9])"), "Harness access-token structure"),
    ("Linear token", re.compile(r"(?<![A-Za-z0-9_])lin_api_[A-Za-z0-9_]{32,128}(?![A-Za-z0-9_])"), "Linear API-token prefix"),
    # Token formats reviewed against Gitleaks v8.24.2. Deliberate offline changes
    # are listed in docs/SECRET_RULE_INVENTORY.csv; tokens are never verified online.
    ("PlanetScale API token", re.compile(r"(?<![\w.-])pscale_tkn_[A-Za-z0-9_=.-]{32,64}(?![\w=.-])"), "PlanetScale API-token prefix"),
    ("PlanetScale OAuth token", re.compile(r"(?<![\w.-])pscale_oauth_[A-Za-z0-9_=.-]{32,64}(?![\w=.-])"), "PlanetScale OAuth-token prefix"),
    ("PlanetScale password", re.compile(r"(?<![\w.-])(?ai:pscale_pw_)[A-Za-z0-9_=.-]{32,64}(?![\w=.-])"), "PlanetScale password prefix"),
    ("Pulumi token", re.compile(r"(?<![\w-])pul-[a-f0-9]{40}(?![\w-])"), "Pulumi API-token prefix"),
    (
        "GitHub token",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})(?![A-Za-z0-9_])"
        ),
        "GitHub token prefix",
    ),
    (
        "Slack token",
        re.compile(r"(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{10,255}(?![A-Za-z0-9-])"),
        "Slack token prefix",
    ),
    (
        "Google API key",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),
        "Google API-key prefix",
    ),
    (
        "Stripe secret key",
        re.compile(
            r"(?<![A-Za-z0-9_])sk_(?:live|test)_[A-Za-z0-9]{16,255}(?![A-Za-z0-9])"
        ),
        "Stripe secret-key prefix",
    ),
    (
        "JWT",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])"
        ),
        "signed JWT structure",
    ),
)

# These names are the wire format shared by every endpoint and the extension.
MECHANISMS = (
    "known_tokens",
    "private_keys",
    "authorization",
    "cookies",
    "urls",
    "assignments",
    "commands",
    "context",
    "heuristics",
    "decoding",
)
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<label>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
    r"[\s\S]*?-----END (?P=label)-----"
)
HEADER = re.compile(
    r"(?i)(?<![\w-])(?P<name>proxy-authorization|authorization|set-cookie|cookie)[\"']?\s*:\s*"
)
ASSIGNMENT = re.compile(
    r"(?i)(?<![\w?&-])(?:password|passwd|pwd|client_secret|api[_-]?key|access[_-]?token|secret[_-]?key)"
    r"\b[\"']?\s*(?:=|:)\s*"
)
COMMAND = re.compile(
    r"(?i)(?:^|\s)(?P<flag>--user|-u|--password|--passwd|--token|--api[_-]?key|"
    r"--client[_-]?secret)(?:=|\s+|(?<=-u)(?=[^\s]))"
)
URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>\"']+")
QUERY_KEY = re.compile(
    r"(?i)^(?:access_token|refresh_token|id_token|token|api[_-]?key|client_secret|password|passwd|pwd|signature|sig)$"
)
AUTH_WORD = re.compile(
    r"(?i)\b(?:auth(?:entication|enticate)?|login|logon|credential|basic)\b"
)
PAIR = re.compile(
    r"(?<![\w:/])(?P<user>[A-Za-z0-9._-]{2,64}):(?P<value>[^\s,:;/\"'{}\[\]]{4,128})(?![\w:])"
)
IDENTIFIER = re.compile(
    r"(?i)^(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|\d+|[0-9a-f]*:[0-9a-f:]+)$"
)
PLACEHOLDER = re.compile(r"⟦[^⟧]*⟧")
MAX_TEXT_LENGTH = 2_000_000
HEURISTIC_SHAPE = r"[0-9a-fA-F]{32,64}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
NET_USE_START = re.compile(
    r'(?i)(?<![\w.])(?:"[A-Za-z]:\\[^"\r\n]*\\net(?:\.exe)?"|'
    r'(?:[A-Za-z]:\\[^\s"\']+\\)?net(?:\.exe)?)\s+use\b'
)


def _windows_tokens(text, start, end):
    """Tokenize one Windows command segment while retaining source spans."""
    tokens = []
    index = start
    while index < end:
        check_work()
        while index < end and text[index].isspace(): index += 1
        if index >= end or text.startswith(("&&", "||"), index) or text[index] == "&": break
        token_start, quoted, chars, content_spans = index, False, [], []
        while index < end:
            if not quoted and (text[index].isspace() or text.startswith(("&&", "||"), index) or text[index] == "&"):
                break
            if text[index] == '"':
                quoted = not quoted; index += 1; continue
            char_start = index
            # Backslashes are ordinary characters for these command forms;
            # quotes delimit but are not part of argv content.
            chars.append(text[index]); index += 1
            content_spans.append((char_start, index))
        if quoted:
            # Incomplete quoting is ambiguous; stop rather than inventing a
            # password and claiming the segment was completely inspected.
            break
        if chars:
            wholly_quoted = text[token_start:token_start + 1] == '"' and index <= end and text[index - 1:index] == '"'
            source_start = content_spans[0][0] if wholly_quoted else token_start
            source_end = content_spans[-1][1] if wholly_quoted else index
            tokens.append(("".join(chars), source_start, source_end))
    return tokens


def _windows_net_use_findings(text: str) -> List[SecretFinding]:
    """Find explicit positional passwords in documented ``net use`` syntax.

    This is a span-preserving Windows tokenizer, not POSIX shlex. It accepts
    quoted arguments without interpreting or executing the command.
    """
    output = []
    for command in NET_USE_START.finditer(text):
        check_work()
        line_end = min([p for p in (text.find("\n", command.end()), text.find(r"\n", command.end())) if p >= 0] or [len(text)])
        tokens = _windows_tokens(text, command.end(), line_end)
        # JSON wrappers or prose after an embedded command terminate at a
        # quote/comma; options remain self-contained tokens.
        share_seen = False
        candidates = []
        destructive = False
        skip_user_value = False
        for value, start, end in tokens:
            lower = value.lower()
            if skip_user_value:
                skip_user_value = False
                continue
            if lower.startswith("/delete") or lower.startswith("/smartcard"):
                destructive = True
            if value.startswith((r"\\", r"\\\\")):
                share_seen = True
                continue
            if lower == "/user:":
                skip_user_value = True
                continue
            if re.fullmatch(r"(?i)[a-z]:|\*", value) or lower.startswith("/user:") or value.startswith("/"):
                continue
            if share_seen and value != "*":
                if PLACEHOLDER.fullmatch(value):
                    continue
                candidates.append((value, start, end))
        if not destructive and len(candidates) == 1:
            value, start, end = candidates[0]
            output.append(SecretFinding(start, end, value, "windows_net_use_password", "Windows net use password argument", "high"))
    return output


def _structured_windows_findings(text: str) -> List[SecretFinding]:
    """Map decoded JSON command findings back to their encoded source spans."""
    output = []
    for _path, decoded, char_spans in _json_string_records(text):
        for finding in _windows_net_use_findings(decoded):
            if finding.start >= len(char_spans) or finding.end <= finding.start:
                continue
            start = char_spans[finding.start][0]
            end = char_spans[finding.end - 1][1]
            output.append(SecretFinding(start, end, text[start:end], finding.kind, finding.reason, "high"))
    return output


def _decode_json_string_spans(text, start, end):
    """Decode one JSON string and map every decoded character to source bytes."""
    import json
    decoded = json.loads(text[start:end])
    spans, index = [], start + 1
    while index < end - 1:
        if index % 4096 == 0: check_work()
        source_start = index
        if text[index] != "\\":
            char = text[index]
            index += 1
        else:
            index += 1
            escape = text[index]
            if escape == "u":
                unit = int(text[index + 1:index + 5], 16); index += 5
                if 0xD800 <= unit <= 0xDBFF and text[index:index + 2] == "\\u":
                    low = int(text[index + 2:index + 6], 16)
                    if 0xDC00 <= low <= 0xDFFF:
                        unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00); index += 6
                char = chr(unit)
            else:
                char = {"b":"\b", "f":"\f", "n":"\n", "r":"\r", "t":"\t"}.get(escape, escape)
                index += 1
        # A decoded surrogate pair is one Python character/source span.
        spans.append((source_start, index))
    return decoded, spans


def _json_string_records(text):
    """Return (path, decoded value, decoded-char source spans) for JSON values."""
    import json
    decoder, records = json.JSONDecoder(), []
    def ws(i):
        while i < len(text) and text[i].isspace(): i += 1
        return i
    def parse(i, path=()):
        i = ws(i)
        if text[i] == "{":
            i = ws(i + 1)
            while text[i] != "}":
                key, key_end = decoder.raw_decode(text, i); i = ws(key_end)
                if not isinstance(key, str) or text[i:i+1] != ":": raise ValueError
                i = parse(i + 1, path + (key.lower(),)); i = ws(i)
                if text[i:i+1] == ",": i = ws(i + 1)
                elif text[i:i+1] != "}": raise ValueError
            return i + 1
        if text[i] == "[":
            i = ws(i + 1)
            while text[i] != "]":
                i = parse(i, path); i = ws(i)
                if text[i:i+1] == ",": i = ws(i + 1)
                elif text[i:i+1] != "]": raise ValueError
            return i + 1
        value, end = decoder.raw_decode(text, i)
        if isinstance(value, str):
            decoded, spans = _decode_json_string_spans(text, i, end)
            records.append((path, decoded, spans))
        return end
    try:
        end = parse(0)
        if ws(end) != len(text): return []
    except (ValueError, TypeError, json.JSONDecodeError, IndexError):
        return []
    return records


# At most this much source text keeps parsed records within one work call.
RECORD_CACHE_CHARS = 32_000_000

# Unique encoded-looking tokens decoded per text: 100, or one per 250
# characters for longer texts. The final check before the AI scans a whole
# batch as one text, so a fixed 100 failed ordinary batches full of IDs and
# slugs that each log passed on its own. Each decode is still bounded (two
# layers, 8 KiB decoded), so the total work grows only with the input size.
DECODE_CANDIDATE_MINIMUM = 100
DECODE_CHARS_PER_CANDIDATE = 250


def decode_candidate_limit(text):
    return max(DECODE_CANDIDATE_MINIMUM, len(text) // DECODE_CHARS_PER_CANDIDATE)


def json_scalar_records(text):
    """Return decoded JSON value records and key spans, preserving source bytes."""
    check_work()
    state = _WORK.get()
    cache = state["records"] if state else None
    if cache is not None and text in cache:
        return cache[text]
    decoder, records, keys = json.JSONDecoder(), [], []

    def ws(index):
        while index < len(text) and text[index].isspace(): index += 1
        return index

    def parse(index, path=()):
        check_work()
        index = ws(index)
        if index >= len(text): raise ValueError
        if text[index] == "{":
            index = ws(index + 1)
            if text[index:index + 1] == "}": return index + 1
            while True:
                key_start = index
                key, key_end = decoder.raw_decode(text, index)
                if not isinstance(key, str): raise ValueError
                keys.append((key_start + 1, key_end - 1))
                index = ws(key_end)
                if text[index:index + 1] != ":": raise ValueError
                index = parse(index + 1, path + (key,)); index = ws(index)
                if text[index:index + 1] == "}": return index + 1
                if text[index:index + 1] != ",": raise ValueError
                index = ws(index + 1)
        if text[index] == "[":
            index = ws(index + 1); item = 0
            if text[index:index + 1] == "]": return index + 1
            while True:
                index = parse(index, path + (item,)); item += 1; index = ws(index)
                if text[index:index + 1] == "]": return index + 1
                if text[index:index + 1] != ",": raise ValueError
                index = ws(index + 1)
        start = index
        value, end = decoder.raw_decode(text, index)
        if isinstance(value, str):
            decoded, spans = _decode_json_string_spans(text, start, end)
            kind, logical = "string", decoded
        elif value is None:
            kind, logical, spans = "null", "null", None
        elif isinstance(value, bool):
            kind, logical, spans = "boolean", "true" if value else "false", None
        else:
            kind, logical, spans = "number", text[start:end], None
        records.append({"path": path, "kind": kind, "start": start, "end": end,
                        "logical": logical, "spans": spans})
        return end

    try:
        end = ws(parse(0))
        result = (records, keys) if end == len(text) else ([], [])
    except (ValueError, TypeError, json.JSONDecodeError, IndexError):
        result = ([], [])
    # Aggregate values retain their SIEM field context without changing source
    # paths/spans. Counts, percentages and query metadata are not field values.
    fields = {}
    for record in result[0]:
        check_work()
        path = record['path']
        if len(path) >= 3 and path[-3] == 'fields' and isinstance(path[-2], int) and path[-1] == 'field' and record['kind'] == 'string':
            fields[path[:-1]] = record['logical']
    if fields:
        for record in result[0]:
            check_work()
            path = record['path']
            for position in range(len(path)-2):
                if path[position] == 'topValues' and isinstance(path[position+1], int) and path[position+2] == 'value':
                    field = fields.get(path[:position])
                    if field:
                        record['statistics_field'] = field
                        record['field_path'] = (field,) + path[position+3:]
                    break
    if cache is not None:
        # The cache lives only inside one bounded work call and is discarded with
        # it, so logs are never kept between requests. Its size is bounded by the
        # amount of source text: stages pass over a whole batch more than once,
        # and a cache of a few documents made large batches reparse every log.
        state["cached_chars"] = state.get("cached_chars", 0) + len(text)
        while cache and state["cached_chars"] > RECORD_CACHE_CHARS:
            evicted, _ = cache.popitem(last=False)
            state["cached_chars"] -= len(evicted)
        cache[text] = result
    return result


class SourceIndex:
    """Ordered scalar/key lookup; never scan every field for every finding."""
    def __init__(self, text):
        self.records, self.keys = json_scalar_records(text)
        self.ends = [record["end"] for record in self.records]

    def normalize(self, findings, decoded=True):
        result = []
        for index, finding in enumerate(findings):
            if index % 128 == 0: check_work()
            key = bisect.bisect_right(self.keys, (finding.start, float("inf"))) - 1
            if key >= 0 and self.keys[key][0] <= finding.start and finding.end <= self.keys[key][1]:
                continue
            position = bisect.bisect_right(self.ends, finding.start)
            scalar = self.records[position] if position < len(self.records) else None
            if self.records and (not scalar or finding.end <= scalar["start"]):
                # A raw assignment can stop on an array/object delimiter. It
                # is not a scalar occurrence and must not destroy JSON syntax.
                continue
            if scalar and scalar["start"] < finding.end:
                if scalar["kind"] != "string":
                    finding = replace(finding, start=scalar["start"], end=scalar["end"],
                                      value=scalar["logical"], scalar_kind=scalar["kind"], source_path=scalar["path"])
                elif (decoded or finding.scalar_kind) and scalar["start"] < finding.start and finding.end < scalar["end"]:
                    spans = scalar["spans"]
                    left = bisect.bisect_right(spans, (finding.start, float("inf"))) - 1
                    right = bisect.bisect_left(spans, (finding.end,))
                    if left >= 0 and right > left:
                        finding = replace(finding, start=spans[left][0], end=spans[right-1][1],
                                          value=scalar["logical"][left:right], scalar_kind="string", source_path=scalar["path"])
            result.append(finding)
        return result


def source_markers(text):
    """Reserve raw AND JSON-decoded source spellings before any allocation."""
    markers = set(PLACEHOLDER.findall(text))
    for record in json_scalar_records(text)[0]:
        markers.update(PLACEHOLDER.findall(record["logical"]))
    return markers


class _LiteralHit:
    def __init__(self, start, end, value): self._start, self._end, self._value = start, end, value
    def start(self): return self._start
    def end(self): return self._end
    def group(self): return self._value


class LiteralMatcher:
    """Small offline Aho-Corasick matcher; build and scan are linear/bounded."""
    def __init__(self, values, bounded, check=None):
        self.bounded = bounded
        self.goto, self.fail, self.output = [{}], [0], [[]]
        for index, value in enumerate(sorted({value for value in values if value})):
            if check and index % 128 == 0: check()
            state = 0
            for offset, char in enumerate(value):
                if offset % 4096 == 0: check_work()
                state = self.goto[state].setdefault(char, len(self.goto))
                if state == len(self.fail):
                    self.goto.append({}); self.fail.append(0); self.output.append([])
            self.output[state].append(value)
        from collections import deque
        queue = deque(self.goto[0].values())
        while queue:
            check_work()
            state = queue.popleft()
            for char, target in self.goto[state].items():
                queue.append(target); fallback = self.fail[state]
                while fallback and char not in self.goto[fallback]: fallback = self.fail[fallback]
                self.fail[target] = self.goto[fallback].get(char, 0)
                self.output[target].extend(self.output[self.fail[target]])

    def finditer(self, text, check=None):
        state = 0
        for index, char in enumerate(text):
            if check and index % 4096 == 0: check()
            while state and char not in self.goto[state]: state = self.fail[state]
            state = self.goto[state].get(char, 0)
            for value in self.output[state]:
                start, end = index + 1 - len(value), index + 1
                if self.bounded and ((start and (text[start-1].isalnum() or text[start-1] == "_"))
                                     or (end < len(text) and (text[end].isalnum() or text[end] == "_"))):
                    continue
                yield _LiteralHit(start, end, value)


def build_literal_matcher(automatic=(), manual=(), check=None):
    """Build request-level literal matchers once, outside scalar loops."""
    return (LiteralMatcher(automatic, True, check) if automatic else None,
            LiteralMatcher(manual, False, check) if manual else None)


def structured_repeat_findings(text, matcher, check=None):
    """Map known/manual values through decoded JSON scalars in linear passes."""
    records, _keys = json_scalar_records(text)
    output = []
    automatic_pattern, manual_pattern = matcher
    for record in records:
        check_work()
        logical = record["logical"]
        for pattern, manual in ((automatic_pattern, False), (manual_pattern, True)):
            if pattern is None:
                continue
            for match in pattern.finditer(logical, check):
                if record["kind"] == "string":
                    spans = record["spans"]
                    start, end = spans[match.start()][0], spans[match.end() - 1][1]
                else:
                    start, end = record["start"], record["end"]
                output.append(SecretFinding(start, end, match.group(),
                                            "manual secret" if manual else "known secret repeat",
                                            "analyst selected: hide everywhere" if manual else "decoded repeat of a detected credential", "high",
                                            record["kind"], record["path"]))
    return output


def structured_detector_findings(text, config=None):
    """Run strong detectors on decoded JSON values and map them to source."""
    records, _keys = json_scalar_records(text)
    if not records:
        return []
    supplied = config.model_dump() if hasattr(config, "model_dump") else dict(config or {})
    enabled = lambda name: supplied.get(name, True)
    decoded_config = dict(supplied)
    decoded_config.update(heuristics=False, decoding=False)
    sensitive_key = re.compile(r"(?i)^(?:password|passwd|pwd|client_secret|api[_-]?key|access[_-]?token|secret[_-]?key)$")
    output = []
    for record in records:
        check_work()
        logical, spans = record["logical"], record["spans"]
        if not logical: continue
        key = next((part for part in reversed(record.get('field_path', record["path"])) if isinstance(part, str)), "")
        start, end = (spans[0][0], spans[-1][1]) if spans else (record["start"], record["end"])
        if enabled("assignments") and sensitive_key.fullmatch(key):
            output.append(SecretFinding(start, end, logical,
                                        "assigned credential", "credential-named JSON field", "high",
                                        record["kind"], record["path"]))
        if key.lower() in ("authorization", "proxy-authorization", "cookie", "set-cookie"):
            cookie = "cookie" in key.lower()
            if enabled("cookies" if cookie else "authorization"):
                scheme = None if cookie else re.match(r"(?i)(?:basic|bearer|digest|token|apikey)\s+", logical)
                offset = scheme.end() if scheme else 0
                if offset < len(logical):
                    output.append(SecretFinding(spans[offset][0] if spans else start, end, logical[offset:],
                                                "cookie" if cookie else "authorization credential",
                                                "HTTP cookie header" if cookie else "HTTP authorization header",
                                                "high", record["kind"], record["path"]))
        if record["kind"] != "string" or not spans:
            continue
        source_content = text[record["start"] + 1:record["end"] - 1]
        if "\\" not in source_content:
            continue
        for finding in detect_secrets(logical, decoded_config):
            if finding.confidence != "high" or finding.start >= finding.end:
                continue
            output.append(SecretFinding(spans[finding.start][0], spans[finding.end - 1][1],
                                        finding.value, finding.kind, finding.reason,
                                        "high", "string", record["path"]))
    return resolve_overlaps(output)


def scan_secrets(text, config=None, field_exclusions=(), heuristic_config=None, custom_rules=None,
                 trusted_markers=(), _fenced=True):
    """Shared endpoint policy: source spans, decoded identities, then custom rules.

    Normalize before AND after union: encoded byte lengths are not logical
    character lengths. Distinct equal-valued occurrences keep distinct spans.
    """
    check_work()
    if not isinstance(text, str) or len(text) > MAX_TEXT_LENGTH:
        # Validate before parsing or splitting: fences cannot bypass the bound.
        raise ValueError("Secret scan requires text within the 2 MB character limit")
    if _fenced:
        fences = list(re.finditer(r"```(?:json)?\s*\n([\s\S]*?)\n```", text, re.I))
        if fences:
            findings, cursor = [], 0
            for fence in fences:
                for start, end in ((cursor, fence.start()), fence.span(1)):
                    findings.extend(replace(f, start=f.start+start, end=f.end+start) for f in
                                    scan_secrets(text[start:end], config, field_exclusions, heuristic_config,
                                                 custom_rules, trusted_markers, _fenced=False))
                cursor = fence.end()
            findings.extend(replace(f, start=f.start+cursor, end=f.end+cursor) for f in
                            scan_secrets(text[cursor:], config, field_exclusions, heuristic_config,
                                         custom_rules, trusted_markers, _fenced=False))
            return findings
    source = SourceIndex(text)
    findings = source.normalize(detect_secrets(text, config, field_exclusions, heuristic_config))
    findings.extend(structured_detector_findings(text, config))
    findings = apply_custom_rules(text, findings, custom_rules)
    return [f for f in source.normalize(resolve_overlaps(findings)) if f.value not in trusted_markers]


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def _shape(value: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value): return "UUID/GUID"
    if re.fullmatch(r"[0-9a-fA-F]{32}", value): return "MD5-like hex"
    if re.fullmatch(r"[0-9a-fA-F]{40}", value): return "SHA-1-like hex"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value): return "SHA-256-like hex"
    return "high-entropy token"


CUSTOM_ACTIONS = {"hide_secret", "hide_privacy", "review", "exclude"}
CUSTOM_SCOPES = {"all", "heuristics", "privacy", "detectors"}
CUSTOM_MODES = {"substring", "token", "full_value"}
CUSTOM_FLAGS = {"i": bounded_regex.IGNORECASE, "m": bounded_regex.MULTILINE, "s": bounded_regex.DOTALL, "x": bounded_regex.VERBOSE}


def _inside_quoted_value(text, position):
    quoted = False
    escaped = False
    for char in text[:position]:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
    return quoted


def _is_full_value(text, start, end):
    """Require an entire JSON/quoted value, or an entire unquoted token."""
    if _inside_quoted_value(text, start):
        return start > 0 and end < len(text) and text[start - 1] == '"' and text[end] == '"'
    return not ((start and re.match(r"[\w-]", text[start - 1])) or
                (end < len(text) and re.match(r"[\w-]", text[end])))


def validate_custom_rules(rules) -> list:
    """Validate declarative user regex policy using the production engine."""
    compiled = []
    for index, rule in enumerate(rules or ()):
        if not rule.get("enabled", True):
            continue
        action, scope, mode = rule.get("action"), rule.get("scope", "all"), rule.get("mode", "substring")
        flags_text = rule.get("flags", "")
        if action not in CUSTOM_ACTIONS or scope not in CUSTOM_SCOPES or mode not in CUSTOM_MODES:
            raise ValueError(f"Invalid custom regex rule {index + 1} configuration")
        if set(flags_text) - set(CUSTOM_FLAGS):
            raise ValueError(f"Unsupported custom regex flags in rule {index + 1}")
        pattern = rule.get("pattern", "")
        if not pattern or len(pattern) > 1000:
            raise ValueError(f"Custom regex rule {index + 1} must contain a pattern of at most 1000 characters")
        flags = sum((CUSTOM_FLAGS[c] for c in set(flags_text)), bounded_regex.VERSION1)
        try:
            expression = bounded_regex.compile(pattern, flags)
            if expression.search("", timeout=.05) is not None:
                raise ValueError(f"Custom regex rule {index + 1} can match an empty string")
        except bounded_regex.error as exc:
            raise ValueError(f"Invalid custom regex rule {index + 1}: {exc}") from None
        capture = rule.get("capture_group", 0)
        if not isinstance(capture, int) or capture < 0 or capture > expression.groups:
            raise ValueError(f"Invalid capture group in custom regex rule {index + 1}")
        compiled.append((rule, expression, capture))
    return compiled


def apply_custom_rules(text: str, findings: Sequence[SecretFinding], rules) -> List[SecretFinding]:
    """Apply bounded custom policy with hide > scoped exclusion > review precedence."""
    compiled = validate_custom_rules(rules)
    if not compiled:
        return resolve_overlaps(findings)
    matches = []
    scalar_records, _key_spans = json_scalar_records(text)
    try:
        for rule, expression, capture in compiled:
            if rule["action"] == "exclude":
                continue
            targets = scalar_records or [{"logical": text, "kind": "raw", "start": 0, "end": len(text), "path": (), "spans": None}]
            for target in targets:
                check_work()
                logical = target["logical"]
                mode = rule.get("mode", "substring")
                candidates = ([expression.fullmatch(logical, timeout=.1)]
                              if mode == "full_value" and target["kind"] != "raw"
                              else expression.finditer(logical, timeout=.1))
                for match in candidates:
                    if match is None:
                        continue
                    start, end = match.span(capture)
                    if start < 0:  # optional capture did not participate
                        continue
                    if start == end:
                        raise ValueError(f"Custom regex rule {rule.get('name') or rule.get('id') or ''} produced an empty match")
                    value = logical[start:end]
                    match_start, match_end = match.span(0)
                    if mode == "token" and ((match_start and (logical[match_start-1].isalnum() or logical[match_start-1] == "_"))
                                             or (match_end < len(logical) and (logical[match_end].isalnum() or logical[match_end] == "_"))):
                        continue
                    if mode == "full_value" and target["kind"] == "raw" and not _is_full_value(text, match.start(), match.end()):
                        continue
                    if target["kind"] == "string":
                        spans = target["spans"]
                        source_start, source_end = spans[start][0], spans[end - 1][1]
                    elif target["kind"] in ("number", "boolean", "null"):
                        source_start, source_end = target["start"], target["end"]
                    else:
                        source_start, source_end = start, end
                    matches.append((source_start, source_end, value, rule, target["kind"], target["path"]))
    except TimeoutError:
        raise ValueError("Custom regex execution limit exceeded; sending stopped") from None

    output = list(findings)
    privacy_hide_spans = []
    for start, end, value, rule, scalar_kind, source_path in matches:
        action = rule["action"]
        rid = rule.get("id") or rule.get("name") or "custom"
        if action == "hide_secret":
            output.append(SecretFinding(start, end, value, "custom regex", f"custom hide rule: {rid}", "high", scalar_kind, source_path))
        elif action == "hide_privacy":
            # Applied by the privacy stage so its mapping is eligible for
            # local restoration. Strong credential findings already present
            # here retain precedence and permanent SECRET masking.
            privacy_hide_spans.append((start, end))
            continue
        elif action == "review":
            output.append(SecretFinding(start, end, value, "custom regex review", f"custom review rule: {rid}", "ambiguous", scalar_kind, source_path))
    for rule, expression, capture in compiled:
        if rule["action"] != "exclude":
            continue
        detector_ids = set(rule.get("detector_ids") or ())
        kept = []
        for finding in output:
            if finding.kind in ("custom regex", "manual secret"):
                kept.append(finding)
                continue
            eligible = finding.confidence == "ambiguous" if rule.get("scope") in ("all", "heuristics") else finding.confidence != "high"
            if rule.get("scope") == "detectors":
                eligible = finding.confidence != "high" and finding.kind in detector_ids
            mode = rule.get("mode", "full_value")
            try:
                matched = expression.fullmatch(finding.value, timeout=.1) if mode == "full_value" else expression.search(finding.value, timeout=.1)
            except TimeoutError:
                raise ValueError("Custom regex execution limit exceeded; sending stopped") from None
            if not (eligible and matched):
                kept.append(finding)
        output = kept
    custom_spans = [(finding.start, finding.end) for finding in output if finding.kind == "custom regex" and finding.confidence == "high"]
    explicit_spans = custom_spans + privacy_hide_spans
    output = [finding for finding in output if not (finding.confidence == "ambiguous" and any(finding.start < end and start < finding.end for start, end in explicit_spans))]
    return resolve_overlaps(output)


def _span(text, start, stops=" ;,}]\r\n\t\"'&"):
    """Read a quoted or unquoted value, retaining source offsets and escapes.

    An unterminated quote is bounded by its physical line. Complete quoted
    assignments can span lines; escaped quotes never terminate a value.
    """
    quote = text[start : start + 1]
    if quote in ('"', "'"):
        start += 1
        end = start
        while end < len(text):
            if end % 4096 == 0: check_work()
            if text[end] == "\\":
                end += 2
                continue
            if text[end] == quote:
                return start, end
            end += 1
        end = text.find("\n", start)
        return start, len(text) if end < 0 else end
    end = start
    while end < len(text) and text[end] not in stops:
        if end % 4096 == 0: check_work()
        end += 1
    return start, end


def _header_end(text, start, separator=";"):
    end = start
    while end < len(text) and text[end] not in "\r\n":
        if end % 4096 == 0: check_work()
        if text[end] in "\"'":
            if end > start and text[end - 1] == "=":
                _, quoted_end = _span(text, end)
                end = quoted_end + 1
                continue
            break
        if text[end].isspace():
            next_field = re.match(r"\s+[\w.-]+=", text[end:])
            if next_field and not text[start:end].rstrip().endswith(separator):
                break
        end += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return end


def _excluded_heuristic_spans(text, field_exclusions=()):
    """Return exact JSON scalar spans with their real key/path provenance."""
    import json
    key_anywhere, exact_paths, metadata_paths = set(), set(), set()
    for item in field_exclusions or ():
        if not item or (isinstance(item, dict) and not item.get("enabled", True)):
            continue
        path = str(item.get("path") if isinstance(item, dict) else item).lower()
        mode = item.get("match_mode") if isinstance(item, dict) else None
        # Internal callers can supply known descriptive field paths without
        # suppressing GUID/hash candidates or any credential detector.
        if isinstance(item, dict) and item.get("metadata_only"):
            metadata_paths.add(tuple(part for part in path.split(".") if part))
            continue
        if mode == "key_anywhere" or (mode is None and "." not in path): key_anywhere.add(path)
        else: exact_paths.add(tuple(part for part in path.split(".") if part))
    metadata_keys = {"_index", "index", "_id", "tags", "provider", "provider_name", "channel", "sourcename", "event_prog"}
    excluded, metadata = [], []
    records, keys = json_scalar_records(text)
    for item in records:
        check_work()
        # Array elements inherit the field's policy; numeric positions are
        # source provenance, not additional object-key names.
        path = tuple(part.lower() for part in item.get('field_path', item["path"]) if isinstance(part, str))
        if item.get('statistics_field'):
            path = tuple(piece for part in path for piece in part.split('.'))
        if not path: continue
        selected = path[-1] in key_anywhere or path in exact_paths
        target = excluded if selected else metadata if path[-1] in metadata_keys or path in metadata_paths else None
        if target is not None:
            start, end = item["start"], item["end"]
            target.append((start + 1, end - 1) if item["kind"] == "string" else (start, end))
    return excluded, metadata, keys


def detect_secrets(text: str, config=None, field_exclusions=(), heuristic_config=None) -> List[SecretFinding]:
    """Raw-text-first, bounded detection; JSON validity is never required."""
    if not isinstance(text, str):
        raise TypeError("secret scanner input must be text")
    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(
            "Secret scan input exceeds the 2 MB character limit; split the logs"
        )
    config = config or {}
    if set(config) - set(MECHANISMS):
        raise ValueError("Unknown secret protection mechanism")
    enabled = lambda name: config.get(name, True)
    found = []
    check_work()
    excluded_spans, metadata_spans, json_key_spans = (_excluded_heuristic_spans(text, field_exclusions)
                                                    if enabled("heuristics") else ([], [], []))
    excluded_spans.sort(); metadata_spans.sort(); json_key_spans.sort()
    def inside(spans, start, end):
        index = bisect.bisect_right(spans, (start, len(text))) - 1
        return index >= 0 and start >= spans[index][0] and end <= spans[index][1]

    def add(start, end, kind, reason, confidence="high"):
        check_work()
        value = text[start:end]
        if value and not PLACEHOLDER.fullmatch(value):
            found.append(SecretFinding(start, end, value, kind, reason, confidence))

    if enabled("known_tokens"):
        for kind, pattern, reason in PROVIDER_RULES:
            check_work()
            for m in pattern.finditer(text):
                add(m.start(), m.end(), kind, reason)
    if enabled("private_keys"):
        for m in PRIVATE_KEY.finditer(text):
            add(m.start(), m.end(), "private key", "complete private-key block")
    for m in HEADER.finditer(text):
        cookie = "cookie" in m["name"].lower()
        if not enabled("cookies" if cookie else "authorization"):
            continue
        start = m.end()
        # JSON header values can start with their own quote; log wrappers end
        # at the next unescaped outer quote. Bearer/Basic keep the scheme.
        a, b = _span(text, start, stops="\r\n\"'" if cookie else "\r\n\"'} ,\t")
        if cookie and text[start : start + 1] not in ('"', "'"):
            b = _header_end(text, start)
        if not cookie:
            quoted = text[start : start + 1] in ('"', "'")
            scheme = re.match(r"(?i)(?:basic|bearer|digest|token|apikey)\s+", text[a:])
            if scheme:
                a += scheme.end()
                if (
                    text[a - scheme.end() : a].lower().startswith("digest")
                    and not quoted
                ):
                    b = _header_end(text, a, separator=",")
                elif not quoted:
                    _, b = _span(text, a, stops="\r\n\"'} ,\t")
            elif not quoted:
                _, b = _span(text, a)
        add(
            a,
            b,
            "cookie" if cookie else "authorization credential",
            "HTTP cookie header" if cookie else "HTTP authorization header",
        )
    if enabled("urls"):
        from urllib.parse import unquote

        for m in URL.finditer(text):
            url = m.group()
            authority_start = url.index("://") + 3
            authority_end = re.search(r"[/\?#]", url[authority_start:])
            authority_end = (
                authority_start + authority_end.start() if authority_end else len(url)
            )
            authority = url[authority_start:authority_end]
            if "@" in authority:
                userinfo = authority[: authority.rfind("@")]
                # Retain the username when a password is present.
                offset = userinfo.find(":") + 1 if ":" in userinfo else 0
                add(
                    m.start() + authority_start + offset,
                    m.start() + authority_start + len(userinfo),
                    "URL password",
                    "credential in URL userinfo",
                )
            query = url.find("?")
            if query >= 0:
                for param in re.finditer(r"(?:[?&])([^=&?#]+)=([^&#]*)", url[query:]):
                    if QUERY_KEY.fullmatch(unquote(param[1])):
                        add(
                            m.start() + query + param.start(2),
                            m.start() + query + param.end(2),
                            "URL token",
                            "sensitive URL query parameter",
                        )
    if enabled("assignments"):
        for m in ASSIGNMENT.finditer(text):
            a, b = _span(text, m.end())
            add(a, b, "assigned credential", "credential-named assignment")
    if enabled("commands"):
        found.extend(_windows_net_use_findings(text))
        found.extend(_structured_windows_findings(text))
        for m in COMMAND.finditer(text):
            a, b = _span(text, m.end(), stops=" \t\r\n\"'")
            if m["flag"].lower() in ("--user", "-u"):
                colon = text.find(":", a, b)
                if colon >= 0:
                    add(colon + 1, b, "command password", "command user credential")
            else:
                add(a, b, "command credential", "credential command argument")
    if enabled("context"):
        for m in PAIR.finditer(text):
            value = m["value"]
            # Strong credential syntax above overrides this identifier guard.
            if IDENTIFIER.fullmatch(value) or m["user"].lower() in (
                "uid",
                "guid",
                "hash",
                "time",
                "timestamp",
                "port",
                "path",
                "status",
                "result",
                "outcome",
                "state",
            ):
                continue
            window = text[max(0, m.start() - 80) : min(len(text), m.end() + 80)]
            if AUTH_WORD.search(window):
                add(
                    *m.span("value"),
                    "possible password",
                    "user:password near authentication text",
                    "ambiguous",
                )
    if enabled("heuristics"):
        occupied = [(f.start, f.end) for f in resolve_overlaps(found) if f.confidence == "high"]
        occupied_ends = [end for _, end in occupied]
        settings = {"min_length": 10, "lowercase_min_length": 14,
                    "entropy_threshold": 3.5, "lowercase_entropy_threshold": 3.15}
        supplied = heuristic_config.model_dump() if hasattr(heuristic_config, "model_dump") else (heuristic_config or {})
        settings.update({key: value for key, value in supplied.items() if value is not None})
        minimum = max(8, min(int(settings["min_length"]), int(settings["lowercase_min_length"])))
        candidate_pattern = re.compile(rf"(?<![A-Za-z0-9_-])(?:{HEURISTIC_SHAPE}|[A-Za-z0-9_-]{{{minimum},128}})(?![A-Za-z0-9_-])")
        for m in candidate_pattern.finditer(text):
            check_work()
            value = m.group()
            entropy = _entropy(value)
            shape = _shape(value)
            if inside(json_key_spans, m.start(), m.end()):
                continue
            if inside(excluded_spans, m.start(), m.end()):
                continue
            # Known metadata suppresses generic tokens, never GUID/hash shapes.
            if shape == "high-entropy token" and inside(metadata_spans, m.start(), m.end()):
                continue
            lowercase = value.isalpha() and value.islower()
            threshold = settings["lowercase_entropy_threshold"] if lowercase else settings["entropy_threshold"]
            min_length = settings["lowercase_min_length"] if lowercase else settings["min_length"]
            structural = False
            if lowercase and len(value) >= min_length:
                vowels = sum(char in "aeiou" for char in value) / len(value)
                unique = len(set(value)) / len(value)
                transitions = sum(a != b for a, b in zip(value, value[1:])) / max(1, len(value)-1)
                structural = vowels <= .32 and unique >= .35 and transitions >= .65
            if not (shape != "high-entropy token" or (len(value) >= min_length and (entropy >= threshold or structural))):
                continue
            occupied_index = bisect.bisect_right(occupied_ends, m.start())
            if occupied_index < len(occupied) and occupied[occupied_index][0] < m.end():
                continue
            evidence = f"Shannon entropy {entropy:.2f} bits/character"
            if structural and entropy < threshold:
                evidence += "; unusual lowercase character structure"
            add(m.start(), m.end(), "uncertain secret candidate", f"{shape}; {evidence}", "ambiguous")
    if enabled("decoding"):
        # Decode only bounded, self-contained tokens. A decoded credential
        # masks the original encoded span so no transient decoded copy leaks.
        from urllib.parse import unquote
        candidates, limit = 0, decode_candidate_limit(text)
        cache = {}
        for m in re.finditer(r"(?<![A-Za-z0-9%_-])(?:[A-Za-z0-9+/_-]{16,}={0,2}|(?:%[0-9A-Fa-f]{2}){4,})(?![A-Za-z0-9%_-])", text):
            raw = m.group()
            # Base64 must have plausible quantum/charset; ordinary metadata
            # words are rejected before they consume the unique-work budget.
            plausible = "%" in raw or (len(raw) % 4 in (0, 2, 3) and ("=" in raw or re.search(r"[0-9+/_-]", raw)))
            if not plausible:
                continue
            if raw in cache:
                if cache[raw]: add(m.start(), m.end(), "encoded credential", cache[raw])
                continue
            if candidates >= limit:
                raise ValueError("Decoded candidate limit exceeded")
            candidates += 1
            decoded, chain, current, total_decoded = None, [], raw, 0
            for _depth in range(2):
                next_value = None
                if "%" in current and re.search(r"%[0-9A-Fa-f]{2}", current):
                    next_value = unquote(current); method = "URL-percent"
                elif re.fullmatch(r"[0-9A-Fa-f]{16,}", current) and len(current) % 2 == 0:
                    try: next_value = bytes.fromhex(current).decode("utf-8"); method = "hex"
                    except (ValueError, UnicodeDecodeError): pass
                else:
                    try:
                        padded = current + "=" * (-len(current) % 4)
                        data = base64.urlsafe_b64decode(padded)
                        next_value = data.decode("utf-8"); method = "Base64/base64url"
                    except (ValueError, UnicodeDecodeError): pass
                if not next_value or next_value == current:
                    break
                total_decoded += len(next_value.encode("utf-8"))
                if total_decoded > 8192:
                    raise ValueError("Decoded byte limit exceeded")
                decoded = current = next_value; chain.append(method)
            if decoded and decoded != raw:
                nested_config = dict(config, decoding=False, heuristics=False)
                if any(f.confidence == "high" for f in detect_secrets(decoded, nested_config)):
                    reason = f"credential found after bounded {' -> '.join(chain)} decoding"
                    cache[raw] = reason
                    add(m.start(), m.end(), "encoded credential", reason)
                else:
                    cache[raw] = None
            else:
                cache[raw] = None
    return resolve_overlaps(found)


def resolve_overlaps(findings: Iterable[SecretFinding]) -> List[SecretFinding]:
    """Union overlapping spans in O(n log n), never leaving credential tails.

    A connected overlap component inherits its strongest evidence. Adjacent
    values remain separate; wrappers outside the spans are untouched.
    """
    ordered = sorted(
        (f for f in findings if f.start < f.end), key=lambda f: (f.start, -f.end)
    )
    chosen = []
    for item in ordered:
        check_work()
        if not chosen or item.start >= chosen[-1].end:
            chosen.append(item)
            continue
        old = chosen[-1]
        end = max(old.end, item.end)
        value = (
            old.value + item.value[max(0, old.end - item.start) :]
            if end > old.end
            else old.value
        )
        strongest = item if (
            (old.confidence != "high" and item.confidence == "high")
            or (item.confidence == old.confidence and item.scalar_kind and not old.scalar_kind)
        ) else old
        if old.start == item.start and old.end == item.end:
            value = strongest.value
        chosen[-1] = SecretFinding(
            old.start,
            end,
            value,
            strongest.kind,
            strongest.reason,
            strongest.confidence,
            strongest.scalar_kind,
            strongest.source_path,
        )
    return chosen


def redact_findings(
    text: str,
    findings: Sequence[SecretFinding],
    allowed: Sequence[str] = (),
    forced: Sequence[str] = (),
    mapping=None,
    reserved=(),
    automatic=(),
    literal_matcher=None,
    check=None,
    reverse_index=None,
) -> tuple[str, dict, List[SecretFinding]]:
    """Exact case-sensitive masking, with a shared placeholder namespace.

    Explicit manual Hide wins over Keep. Existing placeholders are atomic.
    A caller masking many texts with one shared `mapping` can pass
    `reverse_index` ({value: placeholder}, built once from that mapping);
    it is kept up to date here, so it is not rebuilt for every text.
    """
    allowed_set = set(allowed) - set(forced)
    effective = [
        f
        for f in findings
        if not (f.confidence == "ambiguous" and f.value in allowed_set)
    ]
    literal_matcher = literal_matcher or build_literal_matcher(automatic, forced, check)
    for pattern, manual in ((literal_matcher[1], True), (literal_matcher[0], False)):
        if pattern is None:
            continue
        cursor = 0
        for marker in list(PLACEHOLDER.finditer(text)) + [None]:
            end = marker.start() if marker else len(text)
            effective.extend(
                SecretFinding(
                    cursor + m.start(),
                    cursor + m.end(),
                    m.group(),
                    "manual secret" if manual else "known secret repeat",
                    (
                        "analyst selected: hide everywhere"
                        if manual
                        else "exact repeat of a detected credential"
                    ),
                )
                for m in pattern.finditer(text[cursor:end], check)
            )
            cursor = marker.end() if marker else len(text)
    source = SourceIndex(text)
    # Low-level callers keep the simple value-to-marker mapping. The shared
    # scanner adds typed findings for the request-wide policy.
    effective = source.normalize(resolve_overlaps(source.normalize(effective, decoded=False)), decoded=False)
    mapping = mapping if mapping is not None else {}
    by_value = reverse_index if reverse_index is not None else {v: p for p, v in mapping.items()}
    # A name is taken if it is reserved, already in this text, or in the
    # mapping (which also receives every new placeholder). Checking the three
    # directly avoids copying the whole mapping for every text.
    markers = source_markers(text)
    taken = lambda name: name in reserved or name in markers or name in mapping
    pieces, cursor, number = [], 0, len(mapping) + 1
    for f in effective:
        if check: check()
        check_work()
        placeholder = by_value.get(f.value)
        if placeholder is None:
            while taken(f"⟦SECRET#{number}⟧"):
                number += 1
            placeholder = f"⟦SECRET#{number}⟧"
            number += 1
            by_value[f.value] = placeholder
            mapping[placeholder] = f.value
        replacement = json.dumps(placeholder, ensure_ascii=False) if f.scalar_kind in ("number", "boolean", "null") else placeholder
        pieces.extend((text[cursor : f.start], replacement))
        cursor = f.end
    pieces.append(text[cursor:])
    return "".join(pieces), mapping, effective
