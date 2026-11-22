"""
VEILUX backend, served on http://localhost:8000.

- Hides credentials and private values (IPs, users, hosts, domains, your own
  keywords and JSON keys) before logs reach an AI provider, then restores them
  in the answer.
- Reads records from SIEM/SOAR APIs for the extension's connections, including
  search-job APIs that create a search, poll it and then return results.
- Enriches indicators with VirusTotal, AbuseIPDB and WHOIS/RDAP.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict, field_validator
import httpx
import ssl
import certifi
import tldextract
import hashlib
import hmac
import secrets
import logging
from contextlib import asynccontextmanager
from copy import deepcopy
from functools import lru_cache
import json
import os
import re
import regex as bounded_regex
import asyncio
import threading
import time
import uuid
from contextvars import ContextVar
import ipaddress
import ntpath
import posixpath
import sys
import socket
import stat
import subprocess
import tempfile
import base64
from collections import Counter
from typing import List, Optional, Dict, Tuple, Literal
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote, quote
from secret_detection import (detect_secrets, redact_findings, PLACEHOLDER,
                              apply_custom_rules, validate_custom_rules,
                              json_scalar_records,
                              structured_repeat_findings, structured_detector_findings,
                              build_literal_matcher, scan_secrets, source_markers,
                              scanning_work, check_work, resolve_overlaps)

# Windows consoles often default to a legacy codepage (cp1252) that can't
# encode the emoji/Unicode markers this file prints and generates — force
# UTF-8 stdout so it doesn't crash on startup or when logging sanitized data.
# Line buffering shows each message (the pairing code above all) at once, also
# when the output goes to a pipe or a log file.
try:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", line_buffering=True)
except AttributeError:
    pass

VERSION = "1.0.2"  # keep in step with extension/manifest.json
@asynccontextmanager
async def lifespan(_app):
    _open_pairing_window()  # defined with the pairing endpoints below
    yield
    print("🦉 VEILUX backend stopped.", flush=True)


app = FastAPI(title="VEILUX API", version=VERSION, lifespan=lifespan)
# Messages for whoever runs the backend; they stay on this computer.
log = logging.getLogger("veilux")
siem_log = logging.getLogger("veilux.siem")

# ---- Who may call the backend ----
# The backend has no sign-in, and a web page open in the same browser could
# otherwise call it (it can reach internal hosts, lessons and paid lookups).
# Only the VEILUX extension may: browsers mark every cross-origin request from
# a web page with that page's Origin, and requests from an extension carry its
# extension origin (chrome-extension:// in Chrome, Edge, Brave and Opera,
# moz-extension:// in Firefox, safari-web-extension:// in Safari) or no Origin
# at all for simple reads. Any other Origin is refused before the endpoint runs.
#
# A web page can also make its own domain name point at 127.0.0.1 ("DNS
# rebinding") and then read the backend as if it were the same site. Requests
# from a browser must therefore name this computer (or a host named in
# VEILUX_ALLOWED_HOSTS) in their Host header.
#
# VEILUX_ALLOWED_ORIGINS adds exact origins (comma-separated), for example to
# allow a development page.
#
# Those two checks stop web pages, but not other browser extensions: any
# extension may call localhost with its own extension origin. So every request
# must also carry the backend key in an X-Veilux-Token header. The key is
# random, created on first start in a file only this user can read (or taken
# from VEILUX_TOKEN), and never shown in full. The extension gets it once by
# pairing: the backend prints a short pairing code when it starts, the analyst
# enters it in Settings -> Backend, and POST /pair answers with the key. A code
# works for 15 minutes, only from this computer, and stops after 5 wrong tries.
# Only GET /health and POST /pair answer without the key. A request relayed by
# a proxy on this computer counts as coming from another computer: it arrives
# from 127.0.0.1 but carries the proxy's Forwarded or X-Forwarded-For header.
EXTENSION_ORIGIN = re.compile(r"^(chrome-extension|moz-extension|safari-web-extension)://[A-Za-z0-9._-]+$")
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
FORWARDING_HEADERS = ("forwarded", "x-forwarded-for", "x-real-ip")


def _env_list(name):
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


ALLOWED_ORIGINS = set(_env_list("VEILUX_ALLOWED_ORIGINS"))
ALLOWED_HOSTS = {host.lower() for host in _env_list("VEILUX_ALLOWED_HOSTS")}
ACCESS_TOKEN = os.environ.get("VEILUX_TOKEN", "").strip()
# A VEILUX_TOKEN shorter than this is refused at start.
MIN_TOKEN_LENGTH = 16


def default_data_dir() -> str:
    """Where the backend keeps its key, lessons and threat-intelligence cache.

    VEILUX_DATA_DIR wins. The packaged application uses the user's own
    application-data folder, which other accounts cannot read. Run from source,
    the backend keeps using the folder it is started from, as it always has."""
    explicit = os.environ.get("VEILUX_DATA_DIR", "").strip()
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    if not getattr(sys, "frozen", False):
        return ""
    return data_dir_for(system_name(), os.environ, os.path.expanduser("~"))


def system_name(os_name: Optional[str] = None, platform: Optional[str] = None) -> str:
    """"windows", "macos" or "linux" (any other POSIX system is treated as Linux)."""
    os_name = os.name if os_name is None else os_name
    platform = sys.platform if platform is None else platform
    if os_name == "nt":
        return "windows"
    return "macos" if platform == "darwin" else "linux"


def data_dir_for(system: str, environ, home: str) -> str:
    """The packaged backend's data folder on `system`, for a user whose home
    folder is `home`. Paths are joined the way that system writes them, so the
    result does not depend on the computer that computes it."""
    if system == "windows":
        return ntpath.join(environ.get("LOCALAPPDATA") or ntpath.join(home, "AppData", "Local"), "VEILUX")
    if system == "macos":
        return posixpath.join(home, "Library", "Application Support", "VEILUX")
    return posixpath.join(environ.get("XDG_DATA_HOME") or posixpath.join(home, ".local", "share"), "veilux")


def prepare_data_dir(path: str) -> None:
    """Creates the data folder for this user only (0700 on Linux and macOS;
    on Windows the user's AppData folder is already private to them). An
    existing folder is left as it is."""
    if path and not os.path.isdir(path):
        os.makedirs(path, mode=0o700, exist_ok=True)


def data_path(name: str) -> str:
    return os.path.join(DATA_DIR, name) if DATA_DIR else name


DATA_DIR = default_data_dir()
try:
    prepare_data_dir(DATA_DIR)
except OSError as exc:
    sys.exit(f"⛔ Cannot create the data folder {DATA_DIR}: {exc.strerror or exc}. "
             "Set VEILUX_DATA_DIR to a folder you can write to.")
KEY_FILE = os.environ.get("VEILUX_KEY_FILE") or data_path("veilux_backend.key")
PAIRING_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L
PAIRING_CODE_SECONDS = 15 * 60
MAX_PAIRING_FAILURES = 5
PAIRING = {"code": "", "expires": 0.0, "failures": 0}
# Paths that answer without the key. Tests add their own fixtures here.
PUBLIC_PATHS = {"/health", "/pair"}
PUBLIC_PREFIXES: Tuple[str, ...] = ()
# Set when the backend listens on every interface without VEILUX_ALLOWED_HOSTS:
# the names other computers use for it are then unknown.
ANY_HOST = False


def origin_allowed(origin: str) -> bool:
    return origin in ALLOWED_ORIGINS or bool(EXTENSION_ORIGIN.match(origin))


def host_allowed(host_header: str) -> bool:
    host = (host_header or "").strip().lower()
    if host.startswith("["):
        name = host[1:host.find("]")] if "]" in host else host
    else:
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return ANY_HOST or name in LOOPBACK_HOSTS or name in ALLOWED_HOSTS


def token_accepted(sent: Optional[str]) -> bool:
    if not ACCESS_TOKEN:
        return False
    return hmac.compare_digest((sent or "").encode("utf-8"), ACCESS_TOKEN.encode("utf-8"))


class KeyFileError(ValueError):
    """The key file exists but cannot be used safely."""


def _system_tool(*parts: str) -> str:
    # Full path, so a program of the same name in the current folder is never run.
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", *parts)


def _run_quietly(command: List[str]) -> None:
    subprocess.run(command, check=True, capture_output=True, timeout=30)


def restrict_key_file(path: str) -> None:
    """Lets only the current user read and change the key file.

    Linux and macOS: mode 0600, and the file must belong to this user. macOS
    also drops any access-control list a folder passed on to the file.
    Windows: the file no longer inherits the folder's permissions, and only
    this user's account is granted access (icacls, part of Windows)."""
    if os.name == "nt":
        try:
            sid = subprocess.run([_system_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"], check=True,
                                 capture_output=True, text=True, timeout=30).stdout.strip().rsplit(",", 1)[-1].strip('"')
            if not sid.startswith("S-1-"):
                raise OSError("this account's security identifier was not found")
            _run_quietly([_system_tool("icacls.exe"), path, "/inheritance:r", "/grant:r", f"*{sid}:F"])
        except (OSError, subprocess.SubprocessError) as exc:
            raise KeyFileError(f"could not limit {path} to your account ({exc}).") from exc
        return
    info = os.stat(path)
    if info.st_uid != os.geteuid():
        raise KeyFileError(f"{path} belongs to another user. Delete it to create a new one.")
    if stat.S_IMODE(info.st_mode) != 0o600:
        log.warning(f"{path} could be read by other users; it is now private (mode 0600).")
        os.chmod(path, 0o600)
    if sys.platform == "darwin":
        try:
            _run_quietly(["/bin/chmod", "-N", path])
        except (OSError, subprocess.SubprocessError) as exc:
            raise KeyFileError(f"could not remove the access-control list of {path} ({exc}).") from exc


def load_or_create_key(path: str) -> str:
    """Reads the backend key, creating it on first start. Every start checks
    that only this user can read it, and fixes the permissions if needed; a
    key whose permissions cannot be fixed is not used."""
    try:
        with open(path, encoding="utf-8") as handle:
            key = handle.read().strip()
    except FileNotFoundError:
        key = secrets.token_urlsafe(32)
        # O_EXCL also refuses a symbolic link left in the key's place.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            restrict_key_file(path)
        except Exception:
            os.close(descriptor)
            os.remove(path)
            raise
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(key + "\n")
        return key
    if len(key) < MIN_TOKEN_LENGTH:
        raise KeyFileError(f"{path} does not hold a valid backend key. Delete it to create a new one.")
    restrict_key_file(path)
    return key


def new_pairing_code() -> str:
    code = "".join(secrets.choice(PAIRING_CODE_ALPHABET) for _ in range(8))
    PAIRING.update(code=code, expires=time.monotonic() + PAIRING_CODE_SECONDS, failures=0)
    return code[:4] + "-" + code[4:]


def prepare_access() -> str:
    """Sets the backend key (VEILUX_TOKEN, or the key file) and opens a pairing
    window. Returns the pairing code to show to the analyst."""
    global ACCESS_TOKEN
    if not ACCESS_TOKEN:
        ACCESS_TOKEN = load_or_create_key(KEY_FILE)
    return new_pairing_code()


def is_loopback_address(host: str) -> bool:
    """True for this computer's own addresses (127.0.0.0/8, ::1, and IPv4
    loopback written as IPv6), and for the names in LOOPBACK_HOSTS."""
    name = (host or "").strip().strip("[]").lower()
    if name in LOOPBACK_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_loopback


def from_this_computer(request) -> bool:
    # No client address means a Unix socket, which only this computer can open.
    client = request.client
    if client is not None and not is_loopback_address(client.host):
        return False
    return not any(header in request.headers for header in FORWARDING_HEADERS)


def _from_a_browser(request) -> bool:
    headers = request.headers
    return ("sec-fetch-site" in headers or "sec-fetch-mode" in headers or "origin" in headers
            or headers.get("user-agent", "").startswith("Mozilla/"))


class ExtensionCORSMiddleware(CORSMiddleware):
    """CORS answers follow origin_allowed, including origins added at run time."""
    def is_allowed_origin(self, origin: str) -> bool:
        return origin_allowed(origin)


app.add_middleware(
    ExtensionCORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Added after CORSMiddleware, so it runs first and also covers preflight requests.
@app.middleware("http")
async def only_the_extension(request, call_next):
    origin = request.headers.get("origin")
    if origin is not None and not origin_allowed(origin):
        return JSONResponse(status_code=403, content={"detail": "This backend only answers the VEILUX extension. "
                                                                "Requests from web pages are refused."})
    if _from_a_browser(request) and not host_allowed(request.headers.get("host", "")):
        return JSONResponse(status_code=403, content={"detail": "Unknown host name. Open the backend at "
                                                                "http://localhost, or add this name to VEILUX_ALLOWED_HOSTS."})
    # A CORS preflight never carries custom headers; the request that follows it does.
    is_preflight = request.method == "OPTIONS" and "access-control-request-method" in request.headers
    path = request.url.path
    if is_preflight or path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
        return await call_next(request)
    if not token_accepted(request.headers.get("x-veilux-token")):
        refusal = JSONResponse(status_code=401, content={"code": "pairing_required", "detail": (
            "VEILUX is not paired with this backend. Enter the pairing code the backend shows when it starts "
            "in Settings -> Backend, and choose Pair.")})
        # This answer skips the CORS layer; without these headers the extension
        # could not read why it was refused. Web pages never reach this point.
        if origin is not None:
            refusal.headers["Access-Control-Allow-Origin"] = origin
            refusal.headers["Vary"] = "Origin"
        return refusal
    return await call_next(request)

def write_json_atomically(path: str, data) -> None:
    """Writes a temporary file next to path, then swaps it in, so stopping the
    backend mid-write (Ctrl+C, closing its window) never leaves half a file.
    The temporary file is private to this user (mkstemp creates it 0600)."""
    folder = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=".veilux-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise


def load_json_file(path: str, empty, what: str):
    """Reads a JSON data file. A missing file gives `empty`; an unreadable one
    is kept aside as <name>.unreadable, and the backend starts with `empty`
    instead of refusing to start."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, type(empty)):
            return data
        problem = "unexpected content"
    except FileNotFoundError:
        return empty
    except (ValueError, OSError) as exc:
        problem = str(exc)
    kept = path + ".unreadable"
    try:
        os.replace(path, kept)
    except OSError:
        kept = ""
    log.warning(f"{what} could not be read ({problem[:120]}); starting with an empty one."
                + (f" The old file was kept as {kept}." if kept else ""))
    return empty


FEEDBACK_FILE = data_path("training_feedback.json")
# Analyst corrections become lessons. A lesson reaches AI prompts only after the
# analyst approves it in Settings -> Lessons; the newest approved ones are used.
MAX_PROMPT_LESSONS = 10
MAX_STORED_LESSONS = 100

training_data = load_json_file(FEEDBACK_FILE, {"feedback_entries": []}, "The lessons file")
if not isinstance(training_data.get("feedback_entries"), list):
    training_data = {"feedback_entries": []}


def _prepare_lessons(data):
    """Gives every stored correction an id and a status. Corrections saved by
    earlier versions start as pending, so none reaches a prompt unapproved."""
    changed = False
    for entry in data.get("feedback_entries", []):
        if not entry.get("id"):
            entry["id"] = uuid.uuid4().hex
            changed = True
        if entry.get("status") not in ("pending", "approved"):
            entry["status"] = "pending"
            changed = True
    return changed


def _save_training_data():
    write_json_atomically(FEEDBACK_FILE, training_data)


def approved_lessons():
    """Text of the newest approved lessons, oldest first."""
    return [str(entry.get("lesson") or entry.get("user_correction") or "")
            for entry in training_data["feedback_entries"] if entry.get("status") == "approved"][-MAX_PROMPT_LESSONS:]


if _prepare_lessons(training_data):
    try:
        _save_training_data()
    except OSError:
        pass

THREAT_INTEL_CACHE_FILE = data_path("threat_intel_cache.json")
THREAT_INTEL_CACHE_TTL_SECONDS = 24 * 3600  # re-query a given IOC at most once a day

threat_intel_cache = load_json_file(THREAT_INTEL_CACHE_FILE, {}, "The threat-intelligence cache")

# Placeholders look like ⟦IP#1⟧. This rare bracket pair does not occur in JSON,
# PowerShell, CEF, XML or ordinary log text, and needs no regex escaping.
SANITIZE_PREFIX = "⟦"
SANITIZE_SUFFIX = "⟧"
LOG_SEPARATOR = "\n\n---LOG SEPARATOR---\n\n"

# Default internal/private network ranges (IPv4 + IPv6). Users can add their
# own ranges on top of these via the Settings page (internal_cidrs).
DEFAULT_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("fc00::/7"),        # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
]

# Loose candidate matcher for IPv6 literals — validated with ipaddress after
# matching rather than trying to write a fully RFC-4291-correct regex.
IPV6_CANDIDATE_PATTERN = re.compile(r'(?<![\w.:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w.:])')

# File extensions to skip
SKIP_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.sh', '.msi', '.com', '.scr',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.xml', '.json', '.yaml',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.iso',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
    '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wav',
    '.html', '.htm', '.css', '.php', '.asp', '.aspx', '.jsp', '.jspx', '.do', '.action', '.cfm',
    '.log', '.tmp', '.dat', '.db', '.ini', '.cfg', '.conf',
    '.pem', '.crt', '.cer', '.key',
    '.py', '.java', '.cpp', '.c', '.h', '.cs', '.rb', '.go', '.rs', '.ts',
    '.bak', '.old', '.evt', '.evtx'
}

# IANA-reserved / special-use DNS suffixes that never resolve on the public
# internet — always treated as internal, same as RFC1918 IPs. Users can add
# their own org-specific suffixes (e.g. an internal AD domain that happens to
# sit under a real public ccTLD) on top of these via the Settings page
# (internal_domains).
DEFAULT_INTERNAL_DOMAIN_SUFFIXES = [
    "local", "localhost", "localdomain", "internal", "intranet",
    "corp", "home", "lan", "private", "domain", "test", "example",
    "invalid", "home.arpa", "in-addr.arpa", "ip6.arpa",
]


# Request Models
class CustomProviderConfig(BaseModel):
    """An analyst-defined AI endpoint (Settings -> Custom AI Models).

    Covers essentially any model service by naming which request/response
    shape it speaks rather than hardcoding vendors: "openai" fits Groq,
    DeepSeek, Together, OpenRouter, Mistral, Azure OpenAI, and every local
    runner (Ollama, LM Studio, vLLM, llama.cpp) because they all expose an
    OpenAI-compatible /chat/completions; "anthropic" and "gemini" cover the
    two mainstream APIs that don't.
    """
    name: str = "custom"
    api_format: Literal["openai", "anthropic", "gemini"] = "openai"
    endpoint: str                        # full URL to POST to
    model: str                           # model id sent in the request body
    temperature: Optional[float] = Field(default=None, ge=0, le=2, allow_inf_nan=False)
    max_tokens: int = Field(default=4000, ge=1)
    timeout_seconds: float = Field(default=120.0, gt=0, allow_inf_nan=False)
    extra_headers: Optional[Dict[str, str]] = None   # e.g. {"api-version": "..."} for Azure

    @field_validator("api_format", mode="before")
    @classmethod
    def normalize_format(cls, value):
        return (value or "openai").strip().lower() if isinstance(value, str) or value is None else value


class SecretProtection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    known_tokens: bool = True
    private_keys: bool = True
    authorization: bool = True
    cookies: bool = True
    urls: bool = True
    assignments: bool = True
    commands: bool = True
    context: bool = True
    heuristics: bool = True
    decoding: bool = True


class HeuristicSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min_length: int = Field(default=10, ge=8, le=128)
    lowercase_min_length: int = Field(default=14, ge=8, le=128)
    entropy_threshold: float = Field(default=3.5, ge=0.0, le=8.0)
    lowercase_entropy_threshold: float = Field(default=3.15, ge=0.0, le=8.0)


class SecretOptions(BaseModel):
    secret_protection: SecretProtection = Field(default_factory=SecretProtection)
    allowed_ambiguous_secrets: Optional[List[str]] = None
    force_hide_values: Optional[List[str]] = None
    custom_regex_rules: Optional[List[Dict]] = None
    heuristic_field_exclusions: Optional[List[Dict]] = None
    heuristic_settings: Optional[HeuristicSettings] = None


class GenerationSettings(BaseModel):
    """How much a built-in provider may write, and how it reasons. Settings ->
    Providers and API keys -> Advanced. Thinking and effort are only sent where
    the provider documents them (DeepSeek, Claude) and the model reports them."""
    max_output_tokens: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    thinking: Literal["default", "on", "off"] = "default"
    effort: Optional[str] = Field(default=None, pattern=r"^[a-z]{1,12}$")


class LogAnalysisRequest(SecretOptions):
    logs: List[str]
    request_id: Optional[str] = Field(default=None, max_length=80)
    mode: str = "groq"
    sanitize: bool = True
    api_key: Optional[str] = None
    custom_provider: Optional[CustomProviderConfig] = None  # used when mode == "custom"
    openrouter_model: Optional[str] = Field(default=None, max_length=200)  # used when mode == "openrouter"
    # The model the analyst chose for a built-in provider (Settings -> Providers
    # and API keys). There is no built-in default: provider model lists change,
    # so VEILUX never picks or swaps a model on its own.
    model: Optional[str] = Field(default=None, max_length=200)
    generation: Optional[GenerationSettings] = None
    # Granular sanitization controls
    enable_pattern_sanitization: bool = True
    custom_keywords: Optional[Dict[str, str]] = None  # Only enabled keywords
    json_keys_to_hide: Optional[List[str]] = None     # Only enabled keys
    internal_cidrs: Optional[List[str]] = None        # User-defined internal IP ranges
    internal_domains: Optional[List[str]] = None       # User-defined internal domain suffixes
    custom_prompt: Optional[str] = None
    analyst_data: Optional[str] = None
    field_statistics: Optional[List[Dict]] = None
    statistics_fields_to_hide: Optional[List[str]] = None
    output_mode: str = 'separate_logs'
    # Threat intelligence auto-enrichment
    enable_threat_intel: bool = False
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    # Per-source switches from the popup. They default to on, so a client that
    # only sends API keys still gets every source.
    enable_virustotal: bool = True
    enable_abuseipdb: bool = True
    enable_whois: bool = True


class SanitizationRequest(SecretOptions):
    logs: List[str]
    enable_pattern_sanitization: bool = True
    custom_keywords: Optional[Dict[str, str]] = None
    json_keys_to_hide: Optional[List[str]] = None
    internal_cidrs: Optional[List[str]] = None
    analyst_data: Optional[str] = None
    statistics_fields_to_hide: Optional[List[str]] = None
    output_mode: str = 'separate_logs'


class SecretScanRequest(SecretOptions):
    texts: List[str]


class LogAnalysisResponse(BaseModel):
    timings_ms: Dict[str, float] = Field(default_factory=dict)
    analysis: str
    timestamp: str
    sanitized_log: Optional[str] = None
    sanitized_analyst_data: Optional[str] = None
    sanitized_field_statistics: Optional[str] = None
    mapping_table: Optional[Dict[str, str]] = None
    threat_intel_findings: Optional[List[Dict]] = None
    threat_intel_status: Optional[Dict] = None
    secret_findings: Optional[List[Dict]] = None
    # What this request sent to outside services (see _record_ai_request).
    outbound: Optional[Dict] = None


class ThreatIntelLookupRequest(SecretOptions):
    ioc: str
    ioc_type: Optional[Literal['ip', 'domain', 'url', 'hash']] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    enable_virustotal: bool = True
    enable_abuseipdb: bool = True
    enable_whois: bool = True
    use_cache: bool = True


class FeedbackRequest(SecretOptions):
    original_log: str
    analyst_data: Optional[str] = None
    ai_response: str
    user_correction: str


class DefangRequest(BaseModel):
    text: str


class IndicatorRequest(BaseModel):
    logs: List[str]
    internal_cidrs: Optional[List[str]] = None
    internal_domains: Optional[List[str]] = None


class RefangRequest(BaseModel):
    text: str


class SiemFetchRequest(BaseModel):
    """Read records from a SIEM or SOAR API for one connection.

    Built from a connection in the extension (Settings -> Connections):
    link_regex reads values from record links, api_* builds the request from
    those values, and response_path finds the records in the response. Blank
    fields are not filled in: every value comes from the connection.

    fetch_mode selects between two request shapes:
      - "single_request" (default): one request returns the document(s)
        directly. Uses the api_* fields.
      - "search_job": the SIEM runs searches as asynchronous jobs: a request
        creates the job, its status is polled until complete, then the results
        are fetched. Uses the job_* fields; response_path locates the events
        inside the *results* response. The job id captured from the create
        response is available to later templates as ${job_id}.

    context_path_template optionally fetches one extra document per parsed
    link (for example the alert a search is about) and prepends it to the
    returned logs, so the analyst gets that record *and* its events in one
    extraction.
    """
    siem_links: List[str] = []         # record links read from a page (omit for a single-page fetch)
    # Values already read from the page (for example "Alert 42" in the page
    # text) when no link identifies the record. Each dict acts like one link.
    parsed_params: Optional[List[Dict[str, str]]] = None
    siem_base_url: str                 # e.g. "https://siem.example.com"
    auth_type: str = "none"            # "none", "cookie", "basic", "header", or "browser_session"
    auth_cookie: Optional[str] = None  # session cookie value
    auth_cookie_name: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_header_name: Optional[str] = None  # for auth_type="header", e.g. Authorization or a vendor-specific token header
    auth_header_value: Optional[str] = None
    # auth_type="browser_session": the extension forwards the analyst's whole
    # cookie jar for the SIEM origin, and auth_headers_from_cookies echoes
    # chosen cookie values into request headers — the CSRF pattern some
    # products require for session-authenticated API calls.
    auth_cookies: Optional[Dict[str, str]] = None
    auth_headers_from_cookies: Optional[Dict[str, str]] = None  # header name -> cookie name
    # auth_type="oauth_client_credentials": the backend asks the token address
    # for an access token with the OAuth 2.0 client credentials grant (an app
    # registration's client ID and secret) and sends it as a Bearer token. The
    # token is kept in memory only, until shortly before it expires.
    oauth_token_url: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_scope: Optional[str] = None
    verify_ssl: bool = True            # Turn off only for self-signed certificates
    tls_trust: Literal['system', 'bundled'] = 'system'
    ca_bundle_pem: str = Field(default='', max_length=200000)

    # Connection settings, sent in full by the extension.
    link_regex: Optional[str] = None
    api_method: str = "GET"
    api_path_template: Optional[str] = None
    api_headers_template: Optional[Dict[str, str]] = None
    api_body_template: Optional[str] = None
    response_path: Optional[str] = None
    test_path: Optional[str] = None
    result_mode: Literal["first", "records"] = "first"
    record_format: Literal["objects", "columns"] = "objects"
    columns_path: str = ""
    total_path: str = ""
    api_query_template: Optional[Dict[str, str]] = None
    pagination_mode: Literal["none", "offset", "cursor"] = "none"
    pagination_parameter: str = "offset"
    pagination_size_parameter: str = ""
    pagination_cursor_path: str = ""
    page_size: int = Field(default=100, ge=1, le=5000)
    max_pages: int = Field(default=10, ge=1, le=50)
    connector_timeout_seconds: float = Field(default=60, gt=0, le=180)

    # Async search-job fields (fetch_mode="search_job")
    fetch_mode: str = "single_request"
    job_create_method: Optional[str] = None
    job_create_path_template: Optional[str] = None
    job_create_query_template: Optional[Dict[str, str]] = None  # URL query params; values support ${param}
    job_create_body_template: Optional[str] = None              # optional JSON body template
    # "form" sends job_create_query_template as an application/x-www-form-urlencoded
    # body instead of URL parameters (how Splunk documents starting a search).
    job_create_parameters_as: Literal["query", "form"] = "query"
    job_id_path: Optional[str] = None     # dotted path to the job id in the create response
    job_status_path_template: Optional[str] = None   # e.g. "/api/searches/${job_id}"
    job_status_field: Optional[str] = None  # dotted path to the status value in the poll response
    job_complete_values: List[str] = []
    job_error_values: List[str] = []      # empty: a failed job is noticed only when the timeout ends
    job_error_message_path: Optional[str] = None  # where a failed job explains why, in the status response
    job_results_path_template: Optional[str] = None  # e.g. "/api/searches/${job_id}/results"
    job_poll_interval_seconds: float = 2.0
    job_timeout_seconds: float = 90.0
    max_results_per_link: int = Field(default=50, ge=1, le=100000)  # statistics samples can be larger than extractions

    # Optional per-link context document (fetched once, prepended to the logs)
    context_method: str = "GET"
    context_path_template: Optional[str] = None
    context_response_path: Optional[str] = None  # dotted path into the context response (blank = whole body)


# Prompts
PROMPT_NO_SANITIZATION = """You are an expert Tier 2 SOC Analyst. Analyze the provided security log(s) in JSON format. Perform a deep analysis of every field, then produce a concise alert summary following the rules below.

**Output Rules (follow strictly):**

1. **Summary (no header/title):** Start directly with 2-3 sentences describing:
   - What happened (the main event or action detected)
   - The source of the event (source IP, machine, application, user...)
   - The result or outcome (success, failure, blocked, allowed, etc.)
   - If benign, briefly explain why it is not a security threat.

2. **Details:** A header `**Details:**` followed by bullet points of the most relevant fields from the log:
   - Format: `- \\`KeyName:\\` value`
   - Include whichever are relevant: Host, User, Source IP, Destination IP, Port/Service, Process/Command, Event ID, Status, Policy ID, Error Code.
   - Use exact values from the log.
   - If multiple logs are provided: combine shared fields using commas in one bullet (e.g., `- \\`Source IP:\\` 10.0.0.1, 10.0.0.2`) and do NOT repeat information that is identical across logs.

3. **Verdict:** The last bullet point must be:
   `- \\`Verdict:\\` <emoji> <classification>`
   Classifications: ✅ Benign / Legitimate | ⚠️ Suspicious / Operational Issue | 🔴 True Positive / Malicious

**Rules:**
- Start immediately with the summary paragraph — NO introductions, NO "Summary:" header.
- Keep it simple, short, direct, and easy to read.
- Never change the format.

**Example Output:**
A perimeter firewall blocked two inbound TCP connection attempts from external addresses to an internal server on ports that are not published, so no session was established. This matches routine internet scanning stopped by the firewall's default deny policy.

**Details:**
- `Host:` 172.16.84.23
- `Source IP:` 203.0.113.45, 198.51.100.17
- `Destination IP:` 192.0.2.211
- `Port/Service:` Destination ports 8443 and 3389 (TCP)
- `Policy ID:` Default deny
- `Verdict:` ✅ Benign / Legitimate

**Analyze this log:**
"""

PROMPT_WITH_SANITIZATION = """You are an expert Tier 2 SOC Analyst. Analyze the provided security log(s) in JSON format. Perform a deep analysis of every field, then produce a concise alert summary following the rules below.

**Data Handling:**
- Values wrapped in `⟦...⟧` markers are sanitized placeholders. Use them exactly as-is in your output. Do not guess or decode them.

**Output Rules (follow strictly):**

1. **Summary (no header/title):** Start directly with 2-3 sentences describing:
   - What happened (the main event or action detected)
   - The source of the event (source IP, machine, application, user...)
   - The result or outcome (success, failure, blocked, allowed, etc.)
   - If benign, briefly explain why it is not a security threat.

2. **Details:** A header `**Details:**` followed by bullet points of the most relevant fields from the log:
   - Format: `- \\`KeyName:\\` value`
   - Include whichever are relevant: Host, User, Source IP, Destination IP, Port/Service, Process/Command, Event ID, Status, Policy ID, Error Code.
   - Keep values exactly as they appear in the log (including `⟦...⟧` markers).
   - If multiple logs are provided: combine shared fields using commas in one bullet (e.g., `- \\`Source IP:\\` ⟦IP_INT#1⟧, ⟦IP_INT#2⟧`) and do NOT repeat information that is identical across logs.

3. **Verdict:** The last bullet point must be:
   `- \\`Verdict:\\` <emoji> <classification>`
   Classifications: ✅ Benign / Legitimate | ⚠️ Suspicious / Operational Issue | 🔴 True Positive / Malicious

**Rules:**
- Start immediately with the summary paragraph — NO introductions, NO "Summary:" header.
- Keep it simple, short, direct, and easy to read.
- Never change the format.

**Example Output:**
A scheduled task initiated a legitimate Windows `rundll32.exe` process to execute a function from `Startupscan.dll` on host ⟦HOST#1⟧, likely performing a system scan or maintenance operation.

**Details:**
- `Host:` ⟦HOST#1⟧
- `User:` ⟦USER#1⟧
- `Process/Command:` `"C:\\Windows\\system32\\rundll32.exe" Startupscan.dll,SusRunTask`
- `Parent Process:` `C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule`
- `Event ID:` 1 (Process Create)
- `Verdict:` ✅ Benign / Legitimate

**Analyze this log:**
"""


def make_placeholder(category: str, counter: int) -> str:
    return f"{SANITIZE_PREFIX}{category}#{counter}{SANITIZE_SUFFIX}"


_PLACEHOLDER_PATTERN = re.compile(re.escape(SANITIZE_PREFIX) + r'.+?' + re.escape(SANITIZE_SUFFIX))


def is_already_sanitized(text: str) -> bool:
    """Check if a specific value is itself a sanitization placeholder (guards against re-wrapping already-sanitized text)."""
    return bool(_PLACEHOLDER_PATTERN.fullmatch(text))


def is_file_extension(text: str) -> bool:
    text_lower = text.lower()
    return any(text_lower.endswith(ext) for ext in SKIP_EXTENSIONS)


def _looks_like_filename(text: str) -> bool:
    """Same idea as is_file_extension, but excludes .com — which is both a
    legacy DOS executable extension AND, far more commonly today, a real
    TLD. Used where we're specifically trying to identify domains (threat
    intel extraction), where excluding .com would silently drop the single
    most common TLD on the internet."""
    text_lower = text.lower()
    return any(text_lower.endswith(ext) for ext in SKIP_EXTENSIONS if ext != '.com')


def _parse_custom_networks(cidrs: Optional[List[str]]) -> List:
    """Parse user-supplied CIDR strings into ip_network objects, skipping invalid ones."""
    networks = []
    for cidr in (cidrs or []):
        try:
            networks.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
        except (ValueError, AttributeError):
            continue
    return networks


def is_internal_ip(ip_str: str, custom_networks: List) -> bool:
    """Classify an IPv4/IPv6 address as internal using default private ranges plus any user-defined CIDRs."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in DEFAULT_INTERNAL_NETWORKS:
        if addr.version == net.version and addr in net:
            return True
    for net in custom_networks:
        if addr.version == net.version and addr in net:
            return True
    return False


def _parse_custom_domains(domains: Optional[List[str]]) -> List[str]:
    """Normalize user-supplied internal domain suffixes: lowercase, strip whitespace/leading dots."""
    result = []
    for d in (domains or []):
        d = str(d).strip().lower().lstrip(".")
        if d:
            result.append(d)
    return result


def is_internal_domain(domain: str, custom_suffixes: List[str]) -> bool:
    """Classify a domain/hostname as internal — IANA-reserved special-use
    suffixes (.local, .internal, ...) plus any user-defined internal domain
    suffixes, matched exactly or as a parent suffix (e.g. "lab.local" matches
    suffix "local"; "siem.lab.local" matches suffix "lab.local")."""
    domain_l = domain.strip().lower().rstrip(".")
    for suffix in DEFAULT_INTERNAL_DOMAIN_SUFFIXES:
        if domain_l == suffix or domain_l.endswith("." + suffix):
            return True
    for suffix in custom_suffixes:
        if domain_l == suffix or domain_l.endswith("." + suffix):
            return True
    return False


# Defanging rewrites a copy of indicators so they cannot be clicked or
# resolved by accident: the scheme (http -> hxxp, keeping its letter case),
# every dot in a URL's host and in e-mail domains, IPv4 addresses and bare
# domain names (only when they end in a real public suffix, so file names
# such as cmd.exe stay as they are). Paths and query strings are left alone.
# The original evidence is never changed: /defang returns the original next
# to the defanged copy, and refang_text reverses every form written here.
_DEFANG_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DEFANG_TOKENS = re.compile(
    r"(?P<url>\b(?P<scheme>h(?:tt|xx)ps?|ftps?|sftp|wss?)://(?P<authority>[^\s/?#<>\"'`]+))"
    r"|(?P<email>[A-Za-z0-9._%+-]{1,64}@" + _DEFANG_LABEL + r"(?:\." + _DEFANG_LABEL + r")+\b)"
    r"|(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"|(?P<domain>(?<![\w.@/\\-])(?:" + _DEFANG_LABEL + r"\.)+[A-Za-z][A-Za-z0-9-]{0,62}(?![\w-]|\.\w))",
    re.IGNORECASE)


_UNBRACKETED_DOT = re.compile(r"(?<!\[)\.(?!\])")
_UNBRACKETED_AT = re.compile(r"(?<!\[)@(?!\])")


def _defang_scheme(scheme: str) -> str:
    if scheme.lower().startswith("http"):
        return scheme[0] + ("XX" if scheme[1].isupper() else "xx") + scheme[3:]
    return scheme


def _defang_match(match) -> str:
    if match.group("url"):
        authority = match.group("authority")
        trailing = ""
        while authority and authority[-1] in ".,;:)":
            trailing = authority[-1] + trailing
            authority = authority[:-1]
        authority = _UNBRACKETED_AT.sub("[@]", _UNBRACKETED_DOT.sub("[.]", authority))
        return _defang_scheme(match.group("scheme")) + "://" + authority + trailing
    if match.group("email"):
        local, _, domain = match.group("email").rpartition("@")
        return local + "[@]" + domain.replace(".", "[.]")
    if match.group("ipv4"):
        return match.group("ipv4").replace(".", "[.]")
    domain = match.group("domain")
    parts = _ti_public_suffix(domain)
    if parts.suffix and parts.domain:
        return domain.replace(".", "[.]")
    return domain


def defang_text(text: str) -> str:
    return _DEFANG_TOKENS.sub(_defang_match, text)


def refang_text(text: str) -> str:
    result = text
    # hxxp/hXXp/HXXP -> http/http/HTTP (hXXp is how VEILUX 1.0.0 wrote it).
    result = re.sub(r'\b(h)(xx)(ps?)://', lambda m: m.group(1) + ("TT" if m.group(1).isupper() and m.group(2).isupper() else "tt") + m.group(3) + "://",
                    result, flags=re.IGNORECASE)
    result = result.replace('[.]', '.').replace('[dot]', '.')
    result = result.replace('[@]', '@').replace('[at]', '@')
    result = result.replace('[:]', ':')
    return result


def _new_privacy_context(texts=(), secret_mapping=None):
    """Request-local allocator for restorable privacy markers."""
    reserved = set()
    for text in texts or ():
        reserved.update(source_markers(str(text)))
    return {"mapping": {}, "identities": {}, "types": {}, "reserved": reserved, "counters": {},
            "secrets": set(secret_mapping or ())}


def _replace_owned_markers(text, mapping):
    # A single pass: restored text is never scanned again, even if an original
    # value happens to look like a placeholder.
    return PLACEHOLDER.sub(lambda match: mapping.get(match.group(), match.group()), text)


def _owned_marker(context, marker):
    return marker in context["mapping"] or marker in context.get("secrets", ())


def _privacy_marker(context, category, original, value_type="string"):
    # Originals are stored fully restored, so nested hides never need
    # recursive restoration. Placeholder-like text already in the input is
    # reserved, so it can never be confused with one of ours.
    if original in context["mapping"]:
        value_type = context["types"].get(original, value_type)
    original = _replace_owned_markers(original, context["mapping"])
    identity = (category, value_type, original)
    if identity in context["identities"]:
        return context["identities"][identity]
    number = context["counters"].get(category, 0)
    while True:
        number += 1
        marker = f"⟦{category}#{number}⟧"
        if marker not in context["reserved"] and marker not in context["mapping"]:
            break
    context["counters"][category] = number
    context["reserved"].add(marker)
    context["identities"][identity] = marker
    context["mapping"][marker] = original
    context["types"][marker] = value_type
    return marker


def _revoke_restoration_for_secrets(context, secret_mapping, texts, equivalent_values=()):
    """Upgrade prior privacy markers when later strong evidence confirms a secret."""
    context["secrets"].update(secret_mapping or ())
    if not context["mapping"]:
        return list(texts)
    secret_by_value = {value: marker for marker, value in (secret_mapping or {}).items()}
    for group in equivalent_values:
        marker = next((secret_by_value[value] for value in group if value in secret_by_value), None)
        if marker:
            secret_by_value.update({value: marker for value in group})
    secret_pattern, _manual = build_literal_matcher(secret_by_value, (), check_work)
    replacements = {}
    for marker, original in list(context["mapping"].items()):
        check_work()
        matched = next(secret_pattern.finditer(original, check_work), None) if secret_pattern and isinstance(original, str) else None
        secret_marker = secret_by_value.get(original) or (secret_by_value.get(matched.group()) if matched else None)
        if secret_marker:
            replacements[marker] = secret_marker
            del context["mapping"][marker]
            context["types"].pop(marker, None)
    context["identities"] = {identity: marker for identity, marker in context["identities"].items()
                             if marker not in replacements}
    context["secrets"].update(secret_mapping)
    if not replacements:
        return list(texts)
    return [replace_placeholders(text, replacements) for text in texts]


def _json_scalar_records(text):
    """Compatibility view over the authoritative structured-value parser."""
    records, _keys = json_scalar_records(text)
    if not records:
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None
        return [] if isinstance(parsed, (dict, list)) else records
    return [{**record, "char_spans": record.get("spans"),
             "content_end": record["end"] - 1} for record in records]


def _custom_privacy_edits(text, compiled, context):
    """Apply explicit privacy rules to values, preserving JSON syntax/types."""
    if not compiled:
        return text
    records = _json_scalar_records(text)
    candidates = []
    targets = records if records is not None else [{"kind": "raw", "start": 0, "end": len(text), "logical": text}]
    for record in targets:
        check_work()
        logical = record["logical"]
        owned_spans = [(m.start(), m.end()) for m in PLACEHOLDER.finditer(logical) if _owned_marker(context, m.group())]
        for order, (rule, expression, capture) in enumerate(compiled):
            mode = rule.get("mode", "full_value")
            try:
                # A structured full-value rule is anchored to the complete
                # logical scalar. In unstructured logs it is anchored to a
                # delimited evidence token rather than the entire document.
                matches = ([expression.fullmatch(logical, timeout=.1)]
                           if mode == "full_value" and record["kind"] != "raw"
                           else list(expression.finditer(logical, timeout=.1)))
            except TimeoutError:
                raise ValueError("Custom privacy regex execution limit exceeded") from None
            for match in matches:
                if not match: continue
                start, end = match.span(capture)
                if start < 0 or start == end: continue
                if mode == "full_value" and record["kind"] == "raw":
                    delimiters = " \t\r\n=:,;\"'[]{}()"
                    match_start, match_end = match.span(0)
                    if ((match_start and logical[match_start-1] not in delimiters)
                            or (match_end < len(logical) and logical[match_end] not in delimiters)):
                        continue
                match_start, match_end = match.span(0)
                if mode == "token" and ((match_start and (logical[match_start-1].isalnum() or logical[match_start-1] == "_"))
                                         or (match_end < len(logical) and (logical[match_end].isalnum() or logical[match_end] == "_"))):
                    continue
                if record["kind"] in ("number", "boolean", "null"):
                    source_start, source_end = record["start"], record["end"]
                    original, value_type = logical, record["kind"]
                    replacement_quoted = True
                elif record["kind"] == "string":
                    spans = record["char_spans"]
                    source_start = spans[start][0] if start < len(spans) else record["content_end"]
                    source_end = spans[end-1][1] if end else source_start
                    original, value_type = logical[start:end], "string"
                    replacement_quoted = False
                else:
                    source_start, source_end = record["start"] + start, record["start"] + end
                    original, value_type = logical[start:end], "raw"
                    replacement_quoted = False
                if any(start < b and a < end for a, b in owned_spans):
                    continue
                candidates.append((source_start, source_end, order, original, value_type, replacement_quoted))
    chosen = []
    for item in sorted(candidates, key=lambda x: (x[0], x[2], -(x[1]-x[0]))):
        if chosen and item[0] < chosen[-1][1]: continue
        chosen.append(item)
    pieces, cursor = [], 0
    for start, end, _order, original, value_type, quoted in chosen:
        marker = _privacy_marker(context, "CUSTOM_PRIVACY", original, value_type)
        replacement = json.dumps(marker, ensure_ascii=False) if quoted else json.dumps(marker, ensure_ascii=False)[1:-1]
        pieces.extend((text[cursor:start], replacement)); cursor = end
    pieces.append(text[cursor:])
    result = "".join(pieces)
    if records is not None:
        try: json.loads(result)
        except json.JSONDecodeError as exc:
            raise ValueError("Custom privacy rules produced invalid JSON; outbound action stopped") from exc
    return result


def _selected_json_value(path, requested_keys):
    string_path = tuple(str(part).lower() for part in path if not isinstance(part, int))
    for requested in requested_keys or ():
        name = str(requested).lower()
        if string_path and string_path[-1] == name:  # literal dotted key too
            return str(requested)
        nested = tuple(part for part in name.split(".") if part)
        if nested and len(string_path) >= len(nested) and string_path[-len(nested):] == nested:
            return str(requested)
    return None


def _apply_selected_json_hides(text, requested_keys, context, statistics_fields=()):
    """Hide selected JSON scalars by their source record, never parsed spelling."""
    if not requested_keys and not statistics_fields:
        return text
    records, _keys = json_scalar_records(text)
    if not records:
        try:
            json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
        return text
    edits = []
    for record in records:
        check_work()
        selected = (_selected_json_value(record["path"], requested_keys)
                    or _selected_json_value(record.get('field_path', ()), requested_keys))
        field = record.get('statistics_field')
        if field and re.sub(r'[^a-z0-9]', '', field.lower()) in statistics_fields:
            selected = field
        if not selected or _owned_marker(context, record["logical"]):
            continue
        category = selected or "JSON_FIELD"
        marker = _privacy_marker(context, category, record["logical"], record["kind"])
        edits.append((record["start"], record["end"], json.dumps(marker, ensure_ascii=False)))
    result = _apply_source_edits(text, edits)
    json.loads(result)
    return result


def sanitize_logs(logs: List[str],
                  enable_pattern: bool = True,
                  custom_keywords: Optional[Dict[str, str]] = None,
                  json_keys_to_hide: Optional[List[str]] = None,
                  internal_cidrs: Optional[List[str]] = None,
                  statistics_fields_to_hide: Optional[List[str]] = None,
                  custom_regex_rules: Optional[List[Dict]] = None,
                  privacy_context: Optional[Dict] = None) -> Tuple[List[str], Dict[str, str]]:
    """
    - Collect-then-apply: all replacements are gathered first, then applied in one pass
    - JSON-level replacement for structured logs (no blind str.replace)
    - Correct ordering: emails before domains to prevent half-sanitized addresses
    - Case-insensitive dedup for values, O(1) lookups via a lowercase index
    - Longest-match-first application to prevent partial overlaps
    """
    privacy_context = privacy_context or _new_privacy_context(logs)
    for text in logs or ():
        privacy_context["reserved"].update(source_markers(str(text)))
    mapping = privacy_context["mapping"]
    reverse_mapping = {}   # original (exact casing) -> placeholder
    substring_mapping = {} # explicit keywords intentionally match substrings
    lower_index = {}       # lowercased original -> placeholder, for O(1) dedup checks
    sanitized = []

    custom_networks = _parse_custom_networks(internal_cidrs)
    counters = {"user": 0, "ip_int": 0, "ip_ext": 0, "host": 0, "domain": 0, "email": 0, "sid": 0}
    # Never reuse a marker already present in any request input. Apart from
    # collision safety this makes repeated preview scans idempotent.
    for existing in (logs or []):
        for category, number in re.findall(r"⟦([A-Z_]+)#(\d+)⟧", existing):
            key = category.lower()
            if key in counters:
                counters[key] = max(counters[key], int(number))
    normalized_stat_fields = {
        re.sub(r'[^a-z0-9]', '', name.lower())
        for name in (statistics_fields_to_hide or []) if name
    }
    privacy_exclusions = [(rule, expression) for rule, expression, _capture in validate_custom_rules(custom_regex_rules)
                          if rule.get("action") == "exclude" and rule.get("scope") == "privacy"]

    def _is_known(value: str) -> bool:
        return value.lower() in lower_index

    def _register(value: str, placeholder: str, explicit=False):
        """Register a value <-> placeholder pair."""
        if not explicit:
            for rule, expression in privacy_exclusions:
                mode = rule.get("mode", "full_value")
                try:
                    matched = expression.fullmatch(value, timeout=.1) if mode == "full_value" else expression.search(value, timeout=.1)
                except TimeoutError:
                    raise ValueError("Custom privacy exclusion execution limit exceeded") from None
                if matched:
                    return
        generated = re.fullmatch(r"⟦([A-Z_]+)#(\d+)⟧", placeholder)
        if not generated and (placeholder in privacy_context["reserved"] or placeholder in mapping):
            if mapping.get(placeholder) != value:
                placeholder = _privacy_marker(privacy_context, "KEYWORD", value)
        if generated and ((placeholder in mapping and mapping[placeholder] != value)
                          or (placeholder in privacy_context["reserved"] and placeholder not in mapping)):
            category = generated.group(1)
            number = max(int(generated.group(2)), privacy_context["counters"].get(category, 0))
            while True:
                number += 1
                placeholder = f"⟦{category}#{number}⟧"
                if placeholder not in mapping and placeholder not in privacy_context["reserved"]:
                    break
            privacy_context["counters"][category] = number
        mapping[placeholder] = _replace_owned_markers(value, mapping)
        privacy_context["reserved"].add(placeholder)
        reverse_mapping[value] = placeholder
        lower_index[value.lower()] = placeholder
        return placeholder

    # Explicit rules are occurrence-scoped. Their restoration map is not fed
    # into generic request-wide privacy replacement, which would destroy the
    # rule's full-value/token/field semantics.
    privacy_compiled = [(rule, expression, capture) for rule, expression, capture in validate_custom_rules(custom_regex_rules)
                        if rule.get("action") == "hide_privacy"]
    prepared_logs = [
        _apply_selected_json_hides(
            _custom_privacy_edits(original_log, privacy_compiled, privacy_context),
            json_keys_to_hide, privacy_context, normalized_stat_fields)
        for original_log in logs
    ]

    # Detection and replacement are deliberately separate phases.  Otherwise
    # a name first discovered in log N can remain exposed in logs 0..N-1.
    parsed_logs = []
    for log in prepared_logs:
        check_work()
        # ----------------------------------------------------------
        # Step 0: Parse JSON. Work on the object when possible.
        # ----------------------------------------------------------
        try:
            log_json = json.loads(log)
            json_parsed = True
        except (json.JSONDecodeError, TypeError):
            log_json = None
            json_parsed = False
        parsed_logs.append((log, log_json, json_parsed))

        # ===========================================================
        # METHOD 1: Custom Keywords (highest priority — explicit user intent)
        # Case-insensitive match: finds every actual casing variant present
        # in the log and sanitizes each occurrence under the same placeholder.
        # ===========================================================
        if custom_keywords:
            for keyword, replacement in custom_keywords.items():
                if not keyword:
                    continue
                wrapped = f"{SANITIZE_PREFIX}{replacement}{SANITIZE_SUFFIX}"
                for match in re.finditer(re.escape(keyword), log, re.IGNORECASE):
                    actual = match.group(0)
                    # Exact-casing dedup here, not _is_known()'s case-insensitive
                    # check: the apply step below does a case-sensitive substring
                    # replace, so "Jdoe" and "jdoe" each need their own entry
                    # (both pointing at the same placeholder) or one casing
                    # variant would silently never get replaced.
                    if is_already_sanitized(actual) or actual in reverse_mapping:
                        continue
                    allocated = _register(actual, wrapped, explicit=True)
                    substring_mapping[actual] = allocated

        # ===========================================================
        # METHOD 2: JSON Key Filtering (user-specified keys)
        # ===========================================================
        # Explicit JSON fields were already edited by source span above. This
        # avoids parsed-number spelling (1e3 -> 1000.0) and phantom mappings.

        # Selected statistic values were edited above using their real spans
        # and scalar types, alongside selected JSON fields.

        # ===========================================================
        # METHOD 3: Pattern-Based (auto-detection)
        # Order matters: emails BEFORE domains to prevent half-replacement
        # ===========================================================
        if enable_pattern:
            # --- 3a: Usernames — JSON-quoted keys plus unquoted key=value /
            # "key: value" forms (CEF, syslog, and other non-JSON formats) ---
            username_keys = (
                r'TargetUserName|User|Account|LogonUser|username|user_name|userName|'
                r'AccountName|account_name|principal|actor|owner|login|user\.name|source\.user\.name|'
                r'SubjectUserName|SourceUser|DestUser|CallerUser|'
                r'suser|duser|src_user|dst_user'
            )
            user_patterns = [
                rf'"(?:{username_keys})"\s*:\s*"([^"]+)"',
                rf'\b(?:{username_keys})\s*[:=]\s*"?([^\s";,]+)"?',
            ]
            for up in user_patterns:
                for username in set(re.findall(up, log, re.IGNORECASE)):
                    # Two-character account names are common.  Single letters
                    # are too collision-prone for automatic masking.
                    if not username or len(username) < 2 or is_already_sanitized(username) or _is_known(username):
                        continue
                    counters["user"] += 1
                    placeholder = make_placeholder("USER", counters["user"])
                    _register(username, placeholder)

            # Also read the decoded JSON fields: JSON writes ACME\alice as
            # ACME\\alice, and matching only the raw text would miss the
            # decoded spelling of Windows accounts.
            if json_parsed:
                for username in _extract_alias_values(log_json, username_keys):
                    if len(username) < 2 or username == "-" or is_already_sanitized(username) or _is_known(username):
                        continue
                    counters["user"] += 1
                    _register(username, make_placeholder("USER", counters["user"]))

            # --- 3b: Emails (BEFORE domains so the full address is caught) ---
            for email in set(re.findall(r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b', log)):
                if _is_known(email):
                    continue
                counters["email"] += 1
                placeholder = make_placeholder("EMAIL", counters["email"])
                _register(email, placeholder)

            # --- 3c: IPv4 addresses ---
            for ip in set(re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log)):
                if _is_known(ip):
                    continue
                octets = ip.split('.')
                if any(int(o) > 255 for o in octets):
                    continue
                cat = "IP_INT" if is_internal_ip(ip, custom_networks) else "IP_EXT"
                counters[cat.lower()] += 1
                placeholder = make_placeholder(cat, counters[cat.lower()])
                _register(ip, placeholder)

            # --- 3c2: IPv6 addresses (candidate regex, then validated) ---
            for candidate in set(re.findall(IPV6_CANDIDATE_PATTERN, log)):
                if _is_known(candidate):
                    continue
                try:
                    ipaddress.IPv6Address(candidate)
                except ValueError:
                    continue
                cat = "IP_INT" if is_internal_ip(candidate, custom_networks) else "IP_EXT"
                counters[cat.lower()] += 1
                placeholder = make_placeholder(cat, counters[cat.lower()])
                _register(candidate, placeholder)

            # --- 3d: Hostnames — JSON-quoted keys plus unquoted key=value /
            # "key: value" forms ---
            hostname_keys = r'Hostname|Computer|Workstation|host|WorkstationName|DeviceName|MachineName|client_hostname|dvchost|shost|dhost'
            host_patterns = [
                rf'"(?:{hostname_keys})"\s*:\s*"([^"]+)"',
                rf'\b(?:{hostname_keys})\s*[:=]\s*"?([^\s";,]+)"?',
            ]
            for hp in host_patterns:
                for hostname in set(re.findall(hp, log, re.IGNORECASE)):
                    if not hostname or hostname == "-" or is_already_sanitized(hostname) or _is_known(hostname):
                        continue
                    counters["host"] += 1
                    placeholder = make_placeholder("HOST", counters["host"])
                    _register(hostname, placeholder)
            if json_parsed:
                for hostname in _extract_alias_values(log_json, hostname_keys):
                    if not hostname or hostname == '-' or is_already_sanitized(hostname) or _is_known(hostname):
                        continue
                    counters['host'] += 1
                    _register(hostname, make_placeholder('HOST', counters['host']))

            # --- 3e: Domains (emails, UNC paths, and URLs — AFTER emails) ---
            # The file-extension guard only makes sense for the UNC-path form
            # (\\server\payroll.com could genuinely be a file, not a domain);
            # applied to URLs it would wrongly exclude the .com/.net/... TLDs
            # that make up most real domains.
            domain_patterns = [
                (r'@([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})', False),
                (r'\\\\([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})', True),
                (r'https?://([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})', False),
            ]
            for dp, guard_file_ext in domain_patterns:
                for domain in set(re.findall(dp, log)):
                    if _is_known(domain) or (guard_file_ext and is_file_extension(domain)):
                        continue
                    counters["domain"] += 1
                    placeholder = make_placeholder("DOMAIN", counters["domain"])
                    _register(domain, placeholder)

            # --- 3f: Windows domain SIDs (S-1-5-21-... identifies a specific
            # AD domain/account — well-known generic SIDs like S-1-5-18 or
            # S-1-1-0 are intentionally left alone, they carry no domain info) ---
            for sid in set(re.findall(r'\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b', log)):
                if _is_known(sid):
                    continue
                counters["sid"] += 1
                placeholder = make_placeholder("SID", counters["sid"])
                _register(sid, placeholder)

    # ===============================================================
    # APPLY: use the completed request-wide mapping for every input.
    # ===============================================================
    compiled = (_privacy_replacer(reverse_mapping), _keyword_replacer(substring_mapping))
    for log, log_json, json_parsed in parsed_logs:
        if not reverse_mapping:
            sanitized.append(log)
            continue

        if json_parsed and log_json is not None:
            sanitized_log = _apply_replacements_to_json_source(
                log, reverse_mapping, substring_mapping, json_keys_to_hide or (), compiled)
        else:
            sanitized_log = log
            sanitized_log = _replace_privacy_values(sanitized_log, reverse_mapping, compiled[0])
            sanitized_log = _replace_keyword_substrings(sanitized_log, substring_mapping, compiled[1])

        sanitized.append(sanitized_log)

    return sanitized, mapping


def _extract_alias_values(obj, aliases_pattern: str) -> List[str]:
    aliases = re.compile(rf"^(?:{aliases_pattern})$", re.IGNORECASE)
    values = []
    def walk(node):
        if isinstance(node, dict):
            if aliases.fullmatch(str(node.get('field', ''))) and isinstance(node.get('topValues'), list):
                for top in node['topValues']:
                    value = top.get('value') if isinstance(top, dict) else None
                    if isinstance(value, str) and value.strip():
                        values.append(value)
            for key, value in node.items():
                if aliases.fullmatch(str(key)) and isinstance(value, str) and value.strip():
                    values.append(value)
                if isinstance(value, (dict, list)):
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(obj)
    return values


_WORD_RUN = re.compile(r"[A-Za-z0-9_]+")


def _privacy_alternation(alternatives) -> re.Pattern:
    return re.compile(
        r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(v) for v in alternatives) + r")(?![A-Za-z0-9_])",
        re.IGNORECASE,
    )


def _privacy_replacer(reverse_mapping: Dict[str, str]):
    """Compile the privacy pattern for one completed mapping, once per batch.

    Matching is unchanged: every value is replaced case-insensitively where it
    forms a whole token, the longest value first. For speed, each text is
    matched only against the values that can occur in it (see
    _privacy_pattern_for); with thousands of values, trying all of them at
    every position made large batches quadratic."""
    if not reverse_mapping:
        return None
    canonical = {value.lower(): marker for value, marker in reverse_mapping.items()}
    alternatives = sorted(canonical, key=len, reverse=True)
    # For ASCII text and an ASCII value: every word run (letters, digits, "_")
    # of the value must appear as a whole word run of the text where it
    # matches. Punctuation or the start of the value precedes each run, and
    # punctuation, the end of the value or the token boundary follows it. So
    # each value is indexed under its rarest run. Values without letters or
    # digits, and non-ASCII values, are always tried.
    value_runs = {}
    run_counts = Counter()
    for index, value in enumerate(alternatives):
        if value.isascii():
            runs = set(_WORD_RUN.findall(value))
            if runs:
                value_runs[index] = runs
                run_counts.update(runs)
    by_run, always = {}, []
    for index in range(len(alternatives)):
        runs = value_runs.get(index)
        if runs:
            by_run.setdefault(min(runs, key=lambda run: (run_counts[run], run)), []).append(index)
        else:
            always.append(index)
    return {"pattern": _privacy_alternation(alternatives), "canonical": canonical,
            "alternatives": alternatives, "by_run": by_run, "always": always, "cache": {}}


def _privacy_pattern_for(segment: str, compiled):
    """The batch pattern restricted to the values that can match in `segment`,
    in the same order, so the result is identical. Non-ASCII text uses the full
    pattern: case-insensitive matching there has special cases (such as ſ and s)."""
    if not segment.isascii():
        return compiled["pattern"]
    lowered = segment.lower()
    alternatives = compiled["alternatives"]
    indexes = set(compiled["always"])
    for run in set(_WORD_RUN.findall(lowered)):
        # A case-insensitive ASCII match requires the value as a substring.
        indexes.update(i for i in compiled["by_run"].get(run, ()) if alternatives[i] in lowered)
    if not indexes:
        return None
    key = tuple(sorted(indexes))
    cache = compiled["cache"]
    pattern = cache.get(key)
    if pattern is None:
        # Bounded: a batch with very many distinct value sets recompiles some.
        if len(cache) >= 20000:
            cache.clear()
        pattern = cache[key] = _privacy_alternation([alternatives[i] for i in key])
    return pattern


def _privacy_marker_for(matched: str, canonical: Dict[str, str]) -> str:
    marker = canonical.get(matched.lower())
    if marker is not None:
        return marker
    # Case-insensitive matching also pairs characters whose lower() differs,
    # such as "s" and "ſ"; find the value that actually matched.
    return next(m for value, m in canonical.items() if re.fullmatch(re.escape(value), matched, re.IGNORECASE))


def _replace_privacy_values(text: str, reverse_mapping: Dict[str, str], compiled=None) -> str:
    """Replace complete evidence tokens, case-insensitively, outside markers."""
    if not reverse_mapping:
        return text
    compiled = compiled or _privacy_replacer(reverse_mapping)
    canonical = compiled["canonical"]
    pieces, cursor = [], 0
    for marker in list(_PLACEHOLDER_PATTERN.finditer(text)) + [None]:
        end = marker.start() if marker else len(text)
        segment = text[cursor:end]
        pattern = _privacy_pattern_for(segment, compiled)
        pieces.append(pattern.sub(lambda m: _privacy_marker_for(m.group(0), canonical), segment) if pattern else segment)
        if marker:
            pieces.append(marker.group(0))
            cursor = marker.end()
    return "".join(pieces)


def _apply_replacements_to_json_source(text, reverse_mapping, substring_mapping, json_keys=(), compiled=None):
    """Edit JSON value spans without parsing/re-serializing untouched numbers.
    `compiled` holds the batch's precompiled patterns (see _privacy_replacer)."""
    privacy_compiled, keyword_compiled = compiled or (None, None)
    records, _keys = json_scalar_records(text)
    if not records:
        try:
            json.loads(text)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("Structured sanitization lost JSON provenance") from exc
        return text
    literal = {str(key).lower() for key in json_keys}
    nested = {tuple(part.lower() for part in str(key).split(".")) for key in json_keys if "." in str(key)}
    edits = []
    for record in records:
        path = tuple(str(part).lower() for part in record["path"] if not isinstance(part, int))
        selected = bool(path) and (path[-1] in literal or any(len(path) >= len(p) and path[-len(p):] == p for p in nested))
        if record["kind"] == "string":
            replaced = _replace_privacy_values(record["logical"], reverse_mapping, privacy_compiled)
            replaced = _replace_keyword_substrings(replaced, substring_mapping, keyword_compiled)
            if replaced != record["logical"]:
                edits.append((record["start"], record["end"], json.dumps(replaced, ensure_ascii=False)))
        elif selected or (path and path[-1] == "value" and "topvalues" in path):
            marker = reverse_mapping.get(record["logical"])
            if marker:
                edits.append((record["start"], record["end"], json.dumps(marker, ensure_ascii=False)))
    result = _apply_source_edits(text, edits)
    json.loads(result)
    return result


def _keyword_replacer(replacements):
    """Compile the keyword pattern once per batch, like _privacy_replacer."""
    if not replacements:
        return None
    pattern = re.compile("|".join(re.escape(value) for value in sorted(replacements, key=len, reverse=True)), re.IGNORECASE)
    return pattern, {key.lower(): marker for key, marker in replacements.items()}


def _replace_keyword_substrings(text, replacements, compiled=None):
    """Explicit keyword rules retain their historical substring semantics."""
    if not replacements:
        return text
    pattern, canonical = compiled or _keyword_replacer(replacements)
    pieces, cursor = [], 0
    for marker in list(_PLACEHOLDER_PATTERN.finditer(text)) + [None]:
        end = marker.start() if marker else len(text)
        pieces.append(pattern.sub(lambda match: canonical[match.group().lower()], text[cursor:end]))
        if marker:
            pieces.append(marker.group()); cursor = marker.end()
    return "".join(pieces)


def _apply_source_edits(text, edits):
    pieces, cursor = [], 0
    for start, end, replacement in sorted(edits):
        check_work()
        if start < cursor:
            raise ValueError("Overlapping source edits")
        pieces.extend((text[cursor:start], replacement))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def replace_placeholders(analysis: str, mapping: Dict[str, str], privacy_context=None) -> str:
    if not mapping:
        return analysis
    types = (privacy_context or {}).get("types", {})

    def restore_json_source(source):
        # Validate without serializing parsed numbers back through binary float.
        json.loads(source)
        records, _keys = json_scalar_records(source)
        edits = []
        for record in records:
            if record["kind"] != "string":
                continue
            logical = record["logical"]
            if logical in mapping:
                original, original_type = mapping[logical], types.get(logical, "string")
                replacement = original if original_type in ("number", "boolean", "null") else json.dumps(original, ensure_ascii=False)
                if original_type in ("number", "boolean", "null"):
                    json.loads(replacement)
                edits.append((record["start"], record["end"], replacement))
                continue
            restored = _replace_owned_markers(logical, mapping)
            if restored != logical:
                edits.append((record["start"], record["end"], json.dumps(restored, ensure_ascii=False)))
        result = _apply_source_edits(source, edits)
        json.loads(result)
        return result

    stripped = analysis.strip()
    if stripped.startswith(("{", "[", '"')):
        try:
            return restore_json_source(stripped)
        except (json.JSONDecodeError, ValueError):
            # JSON-looking malformed output is not made more corrupt by blind
            # textual substitution; leave its markers unresolved.
            return analysis

    fence = re.compile(r"```(?:json)?\s*\n([\s\S]*?)\n```", re.IGNORECASE)
    def restore_fence(match):
        try:
            restored = restore_json_source(match.group(1))
        except (json.JSONDecodeError, ValueError):
            return match.group(0)
        return "```json\n" + restored + "\n```"
    def restore_prose(value):
        return _replace_owned_markers(value, mapping)
    pieces, cursor = [], 0
    for match in fence.finditer(analysis):
        pieces.append(restore_prose(analysis[cursor:match.start()]))
        pieces.append(restore_fence(match)); cursor = match.end()
    pieces.append(restore_prose(analysis[cursor:]))
    return "".join(pieces)


PROTECTED_SECRET_LABEL = "Protected credential (original withheld; not restorable)"


def public_mapping(privacy_mapping=None, secret_mapping=None) -> Dict[str, str]:
    """Build the analyst-visible mapping without disclosing credentials.

    Privacy originals remain locally restorable. Secret placeholders are
    listed for auditability, but their sensitive originals never cross the API
    response boundary or enter browser storage.
    """
    result = dict(privacy_mapping or {})
    for placeholder in (secret_mapping or {}):
        result.setdefault(placeholder, PROTECTED_SECRET_LABEL)
    return result


def public_secret_findings(findings) -> List[Dict]:
    """Remove originals after local review; spans/reasons remain auditable."""
    return [{**item, "value": PROTECTED_SECRET_LABEL} for item in (findings or [])]


# Each local protection stage stops if it runs longer than its ceiling, so
# runaway work can never hang a request. The ceiling grows with the request
# size, because protecting thousands of logs is legitimately slower.
SCAN_TIMEOUT_SECONDS = 10.0
SCAN_SECONDS_PER_MB = 15.0
SCAN_TIMEOUT_MAX_SECONDS = 900.0
AI_TIMEOUT_SECONDS = 180.0
_request_bytes = ContextVar("request_bytes", default=0)


def local_work_timeout() -> float:
    return min(SCAN_TIMEOUT_MAX_SECONDS, SCAN_TIMEOUT_SECONDS + SCAN_SECONDS_PER_MB * _request_bytes.get() / 1_000_000)


class _RequestSizeMiddleware:
    """Records each request's body size (Content-Length) for local_work_timeout."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        try:
            size = int(dict(scope.get("headers") or []).get(b"content-length", b"0"))
        except ValueError:
            size = 0
        token = _request_bytes.set(max(0, size))
        try:
            await self.app(scope, receive, send)
        finally:
            _request_bytes.reset(token)


app.add_middleware(_RequestSizeMiddleware)
_analysis_jobs = {}
_cancelled_analyses = set()
_job_context = ContextVar("analysis_job", default=None)


# ---- Record of what left this computer ----
# Each request keeps a list of what it sent to outside services: the AI
# provider (destination, model and the exact protected prompt) and every
# threat-intelligence lookup (service, indicator, and whether it was sent or
# answered from the local cache). The extension saves it with the case so the
# analyst can see and export it. API keys are never part of the record.
def _new_outbound():
    return {"ai": None, "lookups": []}


def _record_ai_request(provider: str, model: str, endpoint: str, prompt: str):
    job = _job_context.get()
    if job is None:
        return None
    url = httpx.URL(endpoint)
    entry = {"provider": provider, "model": model,
             # The query string is left out: some services take the key there.
             "endpoint": str(url.copy_with(query=None, fragment=None)),
             "prompt": prompt, "characters": len(prompt),
             "sent_at": datetime.now(timezone.utc).isoformat(), "outcome": "sent"}
    job.setdefault("outbound", _new_outbound())["ai"] = entry
    return entry


def _record_lookup(service: str, ioc: str, ioc_type: str, sent: bool, status: str):
    entry = {"service": service, "indicator": ioc, "type": ioc_type, "sent": sent, "status": status,
             "at": datetime.now(timezone.utc).isoformat()}
    job = _job_context.get()
    if job is not None:
        job.setdefault("outbound", _new_outbound())["lookups"].append(entry)
    return entry


def analysis_phase(label):
    job = _job_context.get()
    if job is not None:
        job["phase"] = label


async def local_work(func, *args, **kwargs):
    started = time.perf_counter()
    cancel_event = threading.Event()
    timeout = local_work_timeout()
    deadline = time.monotonic() + timeout * .95
    def worker():
        with scanning_work(cancel_event, deadline):
            return func(*args, **kwargs)
    try:
        result = await asyncio.wait_for(asyncio.to_thread(worker), timeout)
        job = _job_context.get()
        if job is not None and func is sanitize_logs:
            job['timings_ms']['privacy_masking'] = job['timings_ms'].get('privacy_masking', 0) + (time.perf_counter()-started)*1000
        return result
    except asyncio.CancelledError:
        cancel_event.set()
        raise
    except asyncio.TimeoutError:
        cancel_event.set()
        raise HTTPException(500, f"Local sanitization exceeded its bounded work deadline ({timeout:.0f} s for this request size); "
                                 "sending stopped. Split the logs into smaller batches.") from None
    except Exception as exc:
        # Do not echo scanner exception text: it may contain input secrets.
        # Only these fixed limit messages, which hold no input, are explained.
        reason = _LOCAL_LIMIT_REASONS.get(str(exc)) if isinstance(exc, ValueError) else None
        raise HTTPException(500, "Local sanitization could not complete" + (f" ({reason})" if reason else "") +
                                 "; sending stopped. Split large logs or retry.") from exc


_LOCAL_LIMIT_REASONS = {
    "Decoded candidate limit exceeded": "too many distinct encoded-looking values in one text to inspect",
    "Decoded byte limit exceeded": "an encoded value decodes to more than 8 KiB",
    "Secret scan requires text within the 2 MB character limit": "a text is longer than 2 million characters",
}


def protect_secret_inputs(texts: List[str], allowed=None, forced=None, config=None, mapping=None, custom_rules=None,
                          field_exclusions=None, heuristic_settings=None, reserved_markers=None,
                          cancel_event=None, work_deadline=None, equivalent_values=()):
    """One shared map avoids cascading per-source placeholder renumbering."""
    protected, public_findings = [], []
    mapping = mapping if mapping is not None else {}
    job = _job_context.get()
    scanned = []
    started = time.perf_counter()
    validate_custom_rules(custom_rules)
    def check_budget():
        check_work()
        if (cancel_event is not None and cancel_event.is_set()) or (work_deadline is not None and time.monotonic() >= work_deadline):
            raise TimeoutError("secret protection work budget exhausted")
    # The mapping does not change while scanning, so one set serves every text.
    trusted_markers = set(mapping) | set(reserved_markers or ())
    for text in texts:
        check_budget()
        scanned.append(scan_secrets(text, config, field_exclusions, heuristic_settings, custom_rules, trusted_markers))
    if job is not None:
        job['timings_ms']['detection'] = job['timings_ms'].get('detection', 0) + (time.perf_counter()-started)*1000
    # Strong evidence for a value applies to its other exact occurrences too.
    # This prevents a credential from reappearing as a bare hash on the TI path.
    allowed_set = set(allowed or ()) - set(forced or ())
    exact_values = set(mapping.values())
    exact_values.update(f.value for group in scanned for f in group
                        if f.confidence == 'high' or f.value not in allowed_set)
    # Equivalence is supplied only for request-owned TI hash identities. It
    # never case-folds arbitrary passwords, tokens or the global Keep list.
    for group in equivalent_values:
        if exact_values.intersection(group) or set(forced or ()).intersection(group):
            exact_values.update(group)
    literal_matcher = build_literal_matcher(exact_values, forced or (), check_budget)
    check_budget()
    started = time.perf_counter()
    reserved = {p for text in texts for p in source_markers(text)} | set(reserved_markers or ())
    # Built once and kept in step by redact_findings: only it changes the mapping here.
    reverse_index = {value: placeholder for placeholder, value in mapping.items()}
    for source_index, (text, findings) in enumerate(zip(texts, scanned)):
        check_budget()
        findings = resolve_overlaps(list(findings) + structured_repeat_findings(text, literal_matcher, check_budget))
        redacted, _, effective = redact_findings(
            text, findings, allowed or (), forced or (), mapping, reserved,
            exact_values, literal_matcher, check_budget, reverse_index)
        try:
            json.loads(text)
            was_json = True
        except (json.JSONDecodeError, TypeError):
            was_json = False
        if was_json:
            try:
                json.loads(redacted)
            except json.JSONDecodeError as exc:
                raise ValueError("Credential protection produced invalid JSON; sending stopped") from exc
        protected.append(redacted)
        effective_spans = {(f.start, f.end) for f in effective}
        for finding in findings:
            item = finding.public()
            item.update(source_index=source_index, masked=(finding.start, finding.end) in effective_spans)
            public_findings.append(item)
    if job is not None:
        job['timings_ms']['replacement'] = job['timings_ms'].get('replacement', 0) + (time.perf_counter()-started)*1000

    return protected, mapping, public_findings


@app.get("/analysis/{request_id}/status")
async def analysis_status(request_id: str):
    job = _analysis_jobs.get(request_id)
    return {"phase": job['phase'], "timings_ms": dict(job['timings_ms'])} if job else {"phase": "Preparing analysis"}


@app.post("/analysis/{request_id}/cancel")
async def cancel_analysis(request_id: str):
    _cancelled_analyses.add(request_id)
    asyncio.get_running_loop().call_later(60, _cancelled_analyses.discard, request_id)
    job = _analysis_jobs.get(request_id)
    if job and job.get('task'):
        job['task'].cancel()
    return {"cancelled": bool(job)}


# ============== THREAT INTELLIGENCE ==============
# Enrichment runs on RAW (pre-sanitization) logs and statistic top values —
# reputation lookups need the real IP/domain/hash/URL, not a ⟦PLACEHOLDER⟧. The
# resulting findings text is then fed through sanitize_logs() alongside
# everything else so real IOC values in it get the same placeholders used
# elsewhere, before any of it reaches the AI prompt.

HASH_MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
TI_HASH_PATTERN = re.compile(r'\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b')
IMPHASH_PATTERN = re.compile(r'''(?i)\bIMPHASH["']?\s*[:=]\s*["']?([a-f0-9]{32})(?![a-f0-9])''')
URL_PATTERN = re.compile(r'https?://[^\s"\'<>\\]+')
GENERIC_DOMAIN_PATTERN = re.compile(
    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b'
)
# Same shape as GENERIC_DOMAIN_PATTERN but immediately followed by "=" (or
# CEF's backslash-escaped "\=", used when "=" appears inside an already-CEF
# value like "msg=softfail|spf\=softfail smtp.helo\=mail-lf1-f52.google.com")
# — this is a CEF/key-value field name, not a domain. CEF logs are full of
# dotted field keys that are structurally indistinguishable from a domain by
# shape alone.
CEF_FIELD_KEY_PATTERN = re.compile(GENERIC_DOMAIN_PATTERN.pattern + r'\\?=')
# Same shape but immediately followed by "@" — this is the local part of an
# email address (e.g. "jane.doe@example.org" — "jane.doe" looks
# domain-shaped on its own), not a domain.
EMAIL_LOCALPART_PATTERN = re.compile(GENERIC_DOMAIN_PATTERN.pattern + r'@')
# Same shape but quoted as the value of a JSON "name"/"alias" key — this is a
# SIEM Discover-export column/field definition (e.g.
# {"name":"ad.arcSightEventPath","type":"string","alias":"ad.arcSightEventPath"}),
# not a domain. ArcSight's "ad.*" annotation-dictionary field names in
# particular are dotted and alphabetic, so they're structurally identical to
# a domain by shape alone.
JSON_SCHEMA_FIELD_PATTERN = re.compile(r'"(?:name|alias)":"' + GENERIC_DOMAIN_PATTERN.pattern + r'"')

# Generic backstop for the whole class of bug above: any dotted, alphabetic
# token is structurally indistinguishable from a domain by shape alone,
# whatever log vendor it came from — CEF field names, JSON schema field
# names, Windows/.NET service or class names ("Network.Service",
# "Statssvc.StatsCollector"), etc. The one thing an actual domain has that
# none of those do is a real TLD as its last label. Rather than chase every
# vendor's naming convention individually, require domain candidates to end
# in a TLD that actually exists — ISO 3166-1 ccTLDs plus the common gTLDs.
# Not exhaustive (new/rare gTLDs can be missed), but a missed obscure real
# domain is a far cheaper failure than a burned API call / 400 error on a
# service name that only looked like one.
KNOWN_TLDS = frozenset({
    # ISO 3166-1 alpha-2 country-code TLDs
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az",
    "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz",
    "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cw", "cx", "cy", "cz",
    "de", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "eh", "er", "es", "et", "eu",
    "fi", "fj", "fk", "fm", "fo", "fr",
    "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy",
    "hk", "hm", "hn", "hr", "ht", "hu",
    "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it",
    "je", "jm", "jo", "jp",
    "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz",
    "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly",
    "ma", "mc", "md", "me", "mf", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz",
    "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz",
    "om",
    "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py",
    "qa",
    "re", "ro", "rs", "ru", "rw",
    "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "sv", "sx", "sy", "sz",
    "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz",
    "ua", "ug", "uk", "us", "uy", "uz",
    "va", "vc", "ve", "vg", "vi", "vn", "vu",
    "wf", "ws",
    "ye", "yt",
    "za", "zm", "zw",
    # common legacy + new gTLDs
    "com", "net", "org", "info", "biz", "name", "pro", "mobi", "tel", "asia", "cat", "coop", "jobs",
    "museum", "aero", "travel", "int", "gov", "mil", "edu", "xxx", "post",
    "io", "co", "dev", "app", "xyz", "tech", "online", "site", "store", "shop", "cloud", "club",
    "design", "email", "finance", "health", "host", "icu", "ink", "institute", "link", "live",
    "media", "menu", "money", "network", "news", "ngo", "ninja", "page", "partners", "photo",
    "photos", "pics", "pictures", "pink", "pizza", "place", "plus", "press", "pub", "quest",
    "racing", "radio", "recipes", "red", "rehab", "rent", "rentals", "repair", "report", "rest",
    "restaurant", "review", "reviews", "rip", "rocks", "run", "sale", "salon", "school", "science",
    "services", "shopping", "show", "ski", "social", "software", "solar", "solutions", "song",
    "space", "sport", "stream", "studio", "style", "supplies", "supply", "support", "surf",
    "surgery", "systems", "tattoo", "tax", "taxi", "team", "technology", "tennis", "theater",
    "tips", "tires", "today", "tools", "top", "tours", "town", "toys", "trade", "trading",
    "training", "tube", "university", "uno", "vacations", "ventures", "vet", "video", "vin",
    "vip", "vision", "vote", "voyage", "watch", "webcam", "website", "wedding", "wiki", "win",
    "wine", "work", "works", "world", "wtf", "zone", "group", "global", "guide", "guru",
})


def _has_known_tld(domain: str) -> bool:
    """True if the last label of a domain-shaped candidate is a real, registered
    TLD. See KNOWN_TLDS comment above for why this check exists."""
    return domain.rsplit('.', 1)[-1].lower() in KNOWN_TLDS


# Free-tier reputation APIs (VirusTotal: 4 req/min, 500/day) can't absorb a
# bulk 5000-log Discover extraction's worth of unique IOCs — cap how many
# get looked up per analysis. The disk cache (below) is what makes repeated
# analyses of overlapping IOCs cheap, not a higher cap here.
MAX_IOCS_PER_TYPE = 25
MAX_IOCS_TOTAL = 50

# Wall-clock budget for the whole enrichment phase. Without it, 50 IOCs x
# 2 providers x a 15s timeout could stall an analysis for many minutes
# before the AI call even starts — the single biggest cause of analyses
# that look hung. Enrichment is supplementary, so it yields to the clock.
THREAT_INTEL_TIME_BUDGET_SECONDS = 45.0


def detect_ioc_type(value: str) -> Optional[str]:
    """Classify a single string as ip / domain / url / hash, or None if it's none of those."""
    value = value.strip()
    if value.lower().startswith(('http://', 'https://')):
        return 'url' if urlparse(value).hostname else None
    try:
        ipaddress.ip_address(value)
        return 'ip'
    except ValueError:
        pass
    if re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', value):
        return 'hash'
    try:
        value = _ti_identity(value, 'domain')
    except UnicodeError:
        return None
    if GENERIC_DOMAIN_PATTERN.fullmatch(value) and not _looks_like_filename(value) and _has_known_tld(value):
        return 'domain'
    return None


def extract_iocs(text: str, custom_networks: Optional[List] = None,
                  custom_domains: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Pull candidate IPs, URLs, domains, and hashes out of raw log/context text.
    Internal/private IPs and domains are skipped — public threat-intel feeds
    have no data on them, so looking them up only burns the limited
    per-analysis IOC quota (and some providers 400 on non-public TLDs like
    .local anyway).
    """
    text = re.sub(r'https?://[^\s<>\"\']*⟦[^\s<>\"\']*', '', text)
    iocs = {'ip': [], 'url': [], 'domain': [], 'hash': []}
    seen = set()
    custom_networks = custom_networks or []
    custom_domains = custom_domains or []

    # ArcSight/CEF "Zone URI" fields (deviceZoneURI, sourceZoneURI, ...) embed
    # registry-block boundaries as literal text, e.g.
    # ".../ARIN/204.0.0.0-209.255.255.255 (ARIN)" — describing which registry
    # owns a range, not an IP any event actually used. Both endpoints of any
    # bare "IP-IP" range token get excluded from extraction.
    range_boundary_ips = set()
    for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
        range_boundary_ips.add(m.group(1))
        range_boundary_ips.add(m.group(2))

    for ip in re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text):
        octets = ip.split('.')
        if any(int(o) > 255 for o in octets):
            continue
        if ip in seen or ip in range_boundary_ips or is_internal_ip(ip, custom_networks):
            continue
        seen.add(ip)
        iocs['ip'].append(ip)

    for candidate in set(re.findall(IPV6_CANDIDATE_PATTERN, text)):
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        if candidate in seen or is_internal_ip(candidate, custom_networks):
            continue
        seen.add(candidate)
        iocs['ip'].append(candidate)

    for url in set(re.findall(URL_PATTERN, text)):
        try:
            host = urlparse(url).hostname
        except ValueError:
            host = None

        # Skip URLs pointing at internal infrastructure (an internal IP or a
        # domain under an internal suffix) — same reasoning as skipping the
        # bare IP/domain: public threat-intel feeds have nothing on it, and
        # it just burns quota/clutters findings with an internal SIEM/console link.
        host_is_internal = bool(host) and (is_internal_ip(host, custom_networks) or is_internal_domain(host, custom_domains))
        if host_is_internal:
            continue

        if url not in seen:
            seen.add(url)
            iocs['url'].append(url)
        if host and host not in seen and not _looks_like_filename(host) and _has_known_tld(host):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                seen.add(host)
                iocs['domain'].append(host)

    cef_field_keys = set(re.findall(CEF_FIELD_KEY_PATTERN, text))
    email_localparts = set(re.findall(EMAIL_LOCALPART_PATTERN, text))
    json_schema_fields = set(re.findall(JSON_SCHEMA_FIELD_PATTERN, text))

    for domain in set(re.findall(GENERIC_DOMAIN_PATTERN, text)):
        if (domain in seen or domain in cef_field_keys or domain in email_localparts
                or domain in json_schema_fields
                or _looks_like_filename(domain) or is_internal_domain(domain, custom_domains)
                or not _has_known_tld(domain)):
            continue
        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass
        seen.add(domain)
        iocs['domain'].append(domain)

    import_spans = {match.span(1) for match in IMPHASH_PATTERN.finditer(text)}
    for match in TI_HASH_PATTERN.finditer(text):
        if match.span() in import_spans:
            continue
        h = match.group()
        if h not in seen:
            seen.add(h)
            iocs['hash'].append(h)

    for key in iocs:
        iocs[key] = iocs[key][:MAX_IOCS_PER_TYPE]

    return iocs


def _ti_identity(ioc: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return str(ipaddress.ip_address(ioc))
    if ioc_type == "domain":
        return ioc.rstrip('.').encode('idna').decode('ascii').lower()
    # URL paths and queries are case sensitive.
    return ioc.lower() if ioc_type == "hash" else ioc


def _ti_hash_identity_groups(findings, texts):
    """Carry accepted source identities through canonical TI response spelling."""
    groups = {}
    for finding in findings or ():
        value = finding.get('ioc', '')
        if finding.get('type') == 'hash' and TI_HASH_PATTERN.fullmatch(value):
            groups.setdefault(value.lower(), set()).update((value, value.lower()))
    if groups:
        for text in texts:
            check_work()
            for match in TI_HASH_PATTERN.finditer(text):
                check_work()
                group = groups.get(match.group().lower())
                if group is not None:
                    group.add(match.group())
    return list(groups.values())


# Applied only to structured provider results, never user logs. These fields
# name public entities/services; generic token shape alone is not credential
# evidence. Strong detectors, known repeats, custom rules and explicit hides
# still apply, as do uncertain GUID/hash checks.
TI_METADATA_PATHS = tuple(
    {'path': f'sources.{provider}.{field}', 'match_mode': 'exact_path', 'metadata_only': True}
    for provider, fields in {
        'abuseipdb': ('isp', 'usage_type', 'domain', 'hostnames', 'country_name'),
        'virustotal': ('as_owner', 'registry', 'tags', 'file_type'),
        'whois': ('org', 'network_name', 'registrar', 'nameservers', 'domain', 'requested_domain', 'queried_domain'),
    }.items() for field in fields
)


def _ti_cache_key(ioc: str, ioc_type: str, source: str, api_key: Optional[str]) -> str:
    identity = json.dumps([source, ioc_type, _ti_identity(ioc, ioc_type), api_key or ''])
    # Do not persist credentials. Versioning also invalidates legacy aggregate results.
    version = 'v3-file:' if source == 'virustotal' and ioc_type == 'hash' else 'v2:'
    return version + hashlib.sha256(identity.encode()).hexdigest()


def _get_cached_ti(ioc: str, ioc_type: str, source: str, api_key: Optional[str]) -> Optional[Dict]:
    entry = threat_intel_cache.get(_ti_cache_key(ioc, ioc_type, source, api_key))
    if not isinstance(entry, dict):
        return None
    if (datetime.now().timestamp() - entry.get("cached_at", 0)) > THREAT_INTEL_CACHE_TTL_SECONDS:
        return None
    result = entry.get("result")
    return deepcopy(result) if isinstance(result, dict) and result.get('status') == 'ok' else None


def _set_cached_ti(ioc: str, ioc_type: str, source: str, api_key: Optional[str], result: Dict):
    threat_intel_cache[_ti_cache_key(ioc, ioc_type, source, api_key)] = {
        "result": deepcopy(result),
        "cached_at": datetime.now().timestamp()
    }


def _save_threat_intel_cache():
    try:
        write_json_atomically(THREAT_INTEL_CACHE_FILE, threat_intel_cache)
    except Exception as e:
        log.warning(f"Failed to save threat intel cache: {e}")


async def query_virustotal(client: httpx.AsyncClient, ioc: str, ioc_type: str, api_key: str) -> Optional[Dict]:
    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{quote(ioc, safe='')}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{quote(ioc, safe='')}"
        elif ioc_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{quote(ioc, safe='')}"
        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return None

        response = await client.get(url, headers={"x-apikey": api_key}, timeout=15.0)

        if response.status_code == 404:
            # Not previously scanned. We deliberately don't submit-and-wait
            # for a fresh scan here — that burns quota fast and adds latency
            # disproportionate to a single log analysis.
            return {"status": "not_found"}
        if response.status_code == 429:
            return {"status": "rate_limited"}
        if response.status_code != 200:
            return {"status": "error", "detail": f"HTTP {response.status_code}"}

        attrs = response.json()['data']['attributes']
        stats = attrs.get('last_analysis_stats') or {}
        counts = [_ti_count(v) for v in stats.values()]
        result = {
            "status": "ok",
            "malicious": _ti_count(stats.get("malicious")),
            "suspicious": _ti_count(stats.get("suspicious")),
            "total_engines": sum(counts) if counts and all(v is not None for v in counts) else None,
            "asn": _ti_count(attrs.get('asn')), "as_owner": attrs.get('as_owner'),
            "country": attrs.get('country'), "network": attrs.get('network'),
            "registry": attrs.get('regional_internet_registry'),
            "reputation": attrs.get('reputation'), "last_analysis_date": attrs.get('last_analysis_date'),
            "categories": attrs.get('categories'), "tags": attrs.get('tags'),
            "link": f"https://www.virustotal.com/gui/search/{quote(ioc, safe='')}"
        }
        if ioc_type == 'hash':
            result.update(file_name=attrs.get('meaningful_name'), file_type=attrs.get('type_description'),
                          file_size=_ti_count(attrs.get('size')), first_submission_date=attrs.get('first_submission_date'),
                          times_submitted=_ti_count(attrs.get('times_submitted')))
        return result
    except httpx.TimeoutException:
        return {"status": "timeout", "detail": "VirusTotal did not respond in time."}
    except Exception:
        return {"status": "error", "detail": "Could not read the VirusTotal response."}


def _ti_count(value, maximum=None):
    """Missing/malformed numbers must not turn into a zero or a clean verdict."""
    return value if type(value) is int and value >= 0 and (maximum is None or value <= maximum) else None


async def query_abuseipdb(client: httpx.AsyncClient, ip: str, api_key: str) -> Optional[Dict]:
    try:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=15.0
        )
        if response.status_code == 429:
            return {"status": "rate_limited"}
        if response.status_code != 200:
            return {"status": "error", "detail": f"HTTP {response.status_code}"}

        data = response.json()['data']
        return {
            "status": "ok",
            "ip_address": data.get('ipAddress') or ip,
            "abuse_confidence_score": _ti_count(data.get("abuseConfidenceScore"), 100),
            "total_reports": _ti_count(data.get("totalReports")),
            "report_window_days": 90,
            "distinct_reporters": _ti_count(data.get('numDistinctUsers')),
            "country": data.get("countryCode"),
            "country_name": data.get('countryName'),
            "isp": data.get('isp'), "usage_type": data.get('usageType'),
            "domain": data.get('domain'), "hostnames": data.get('hostnames'),
            "ip_version": data.get('ipVersion'), "is_public": data.get('isPublic'),
            "is_whitelisted": data.get('isWhitelisted'), "is_tor": data.get('isTor'),
            "last_reported_at": data.get('lastReportedAt'),
            # The documented check API supplies neither ASN nor city nor WHOIS.
            "asn": None, "city": None,
            "link": f"https://www.abuseipdb.com/check/{ip}"
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "detail": "AbuseIPDB did not respond in time."}
    except Exception:
        return {"status": "error", "detail": "Could not read the AbuseIPDB response."}


# Age below which a freshly-registered domain is itself a signal: phishing
# and C2 infrastructure is typically days old, legitimate business domains
# rarely are.
NEW_DOMAIN_SUSPICIOUS_DAYS = 30


def _rdap_entity_contact(entities: List[Dict], want_role: str) -> Optional[Dict]:
    """Pull a named role (registrar, abuse, registrant) out of RDAP's nested
    entity/vCard structure, which is verbose but standardized (RFC 7483)."""
    for entity in entities or []:
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        if want_role in roles:
            name, email = None, None
            for item in (entity.get("vcardArray") or [None, []])[1] or []:
                if not isinstance(item, list) or len(item) < 4:
                    continue
                if item[0] == "fn" and not name:
                    name = item[3]
                elif item[0] == "email" and not email:
                    email = item[3]
            return {"name": name, "email": email}
        nested = _rdap_entity_contact(entity.get("entities") or [], want_role)
        if nested:
            return nested
    return None


def _rdap_event_date(events: List[Dict], action: str) -> Optional[str]:
    for event in events or []:
        if str(event.get("eventAction", "")).lower() == action:
            return event.get("eventDate")
    return None


def _days_since(iso_date: Optional[str]) -> Optional[int]:
    if not iso_date:
        return None
    try:
        cleaned = str(iso_date).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - parsed).days, 0)
    except (ValueError, TypeError):
        return None


# Use the bundled Public Suffix List; never fetch/update it during a lookup.
_ti_public_suffix = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


async def query_rdap(client: httpx.AsyncClient, ioc: str, ioc_type: str) -> Optional[Dict]:
    """Registration/ownership lookup via RDAP — the IETF's structured
    successor to WHOIS. Free, no API key, no registration: rdap.org
    bootstraps to the authoritative registry (ARIN/RIPE/APNIC for IPs, the
    TLD registry for domains) and answers JSON instead of scraped text.

    For an IP this answers "whose network is this?" (netname, org, country,
    abuse contact); for a domain "who registered it and when?" — and domain
    age is a genuine triage signal in its own right.
    """
    if ioc_type not in ("ip", "domain"):
        return None
    queried = _ti_identity(ioc, ioc_type)
    if ioc_type == 'domain':
        queried = _ti_public_suffix(queried).top_domain_under_public_suffix or queried
    scope = {'requested_domain': ioc, 'queried_domain': queried} if ioc_type == 'domain' else {}
    url = f"https://rdap.org/{'ip' if ioc_type == 'ip' else 'domain'}/{quote(queried, safe='')}"
    try:
        response = await client.get(url, headers={"Accept": "application/rdap+json"},
                                    timeout=15.0, follow_redirects=True)
        if response.status_code == 404:
            return {"status": "not_found", **scope,
                    "note": "No RDAP record available. This does not establish whether the domain is registered."}
        if response.status_code == 429:
            return {"status": "rate_limited"}
        if response.status_code != 200:
            return {"status": "error", "detail": f"HTTP {response.status_code}"}

        data = response.json()
        entities = data.get("entities") or []
        events = data.get("events") or []
        abuse = _rdap_entity_contact(entities, "abuse")
        if not isinstance(data, dict) or not any(data.get(k) for k in ('ldhName', 'unicodeName', 'handle', 'name', 'startAddress')):
            return {"status": "error", "detail": "The registry returned no usable registration record.", **scope}
        result = {"status": "ok", "registered": True, "source": "RDAP", **scope}

        if ioc_type == "ip":
            result.update({
                "network_name": data.get("name"),
                "network_range": f"{data.get('startAddress')} - {data.get('endAddress')}"
                                 if data.get("startAddress") else None,
                "cidr": ', '.join(str(c.get('v4prefix') or c.get('v6prefix')) + '/' + str(c['length'])
                                  for c in data.get('cidr0_cidrs', [])
                                  if (c.get('v4prefix') or c.get('v6prefix')) and type(c.get('length')) is int) or None,
                "org": (_rdap_entity_contact(entities, "registrant")
                        or _rdap_entity_contact(entities, "administrative") or {}).get("name"),
                "country": data.get("country"),
                "assigned": _rdap_event_date(events, "registration"),
            })
        else:
            created = _rdap_event_date(events, "registration")
            age_days = _days_since(created)
            result.update({
                "domain": data.get("ldhName") or queried,
                "registrar": (_rdap_entity_contact(entities, "registrar") or {}).get("name"),
                "created": created,
                "age_days": age_days,
                "expires": _rdap_event_date(events, "expiration"),
                "last_changed": _rdap_event_date(events, "last changed"),
                "status_flags": data.get("status"),
                "nameservers": [ns.get("ldhName") for ns in (data.get("nameservers") or [])][:5],
            })
            if age_days is not None and age_days <= NEW_DOMAIN_SUSPICIOUS_DAYS:
                result["newly_registered"] = True
                result["note"] = f"registered {age_days} day(s) ago"

        if abuse:
            result["abuse_contact"] = abuse.get("email") or abuse.get("name")
        return result
    except httpx.TimeoutException:
        return {"status": "timeout", "detail": "The registration service did not respond in time.", **scope}
    except Exception:
        return {"status": "error", "detail": "Could not read the registration service response.", **scope}


async def lookup_ioc(client: httpx.AsyncClient, ioc: str, ioc_type: str,
                      virustotal_api_key: Optional[str], abuseipdb_api_key: Optional[str],
                      use_cache: bool = True, enable_virustotal: bool = True,
                      enable_abuseipdb: bool = True, enable_whois: bool = True,
                      timeout_seconds: float = 15.0) -> Dict:
    """Independent provider caches and bounded parallel reads for one IOC.

    Errors are retried next time, source switches apply even to cached data,
    and a slow registry cannot discard a successful reputation response.
    """
    ioc = _ti_identity(ioc, ioc_type)
    providers = []
    if enable_virustotal and virustotal_api_key and ioc_type in ("ip", "domain", "hash", "url"):
        providers.append(('virustotal', virustotal_api_key, query_virustotal, (client, ioc, ioc_type, virustotal_api_key)))
    if enable_abuseipdb and abuseipdb_api_key and ioc_type == "ip":
        providers.append(('abuseipdb', abuseipdb_api_key, query_abuseipdb, (client, ioc, abuseipdb_api_key)))
    if enable_whois and ioc_type in ("ip", "domain"):
        providers.append(('whois', None, query_rdap, (client, ioc, ioc_type)))

    async def read_provider(name, key, query, args):
        cached = _get_cached_ti(ioc, ioc_type, name, key) if use_cache else None
        if cached is not None:
            _record_lookup(name, ioc, ioc_type, False, 'answered from the local cache')
            return name, {**cached, 'cached': True}
        if timeout_seconds <= 0:
            _record_lookup(name, ioc, ioc_type, False, 'skipped: lookup time limit reached')
            return name, {'status': 'skipped', 'detail': 'Analysis lookup time limit reached.', 'cached': False}
        record = _record_lookup(name, ioc, ioc_type, True, 'sent')
        try:
            value = await asyncio.wait_for(query(*args), timeout=min(15.0, timeout_seconds))
            value = dict(value or {'status': 'error', 'detail': 'No provider response.'})
        except asyncio.TimeoutError:
            value = {'status': 'timeout', 'detail': 'The service did not respond within the lookup time limit.'}
        except Exception:
            value = {'status': 'error', 'detail': 'The service lookup failed.'}
        value.update(cached=False, checked_at=datetime.now(timezone.utc).isoformat())
        record['status'] = 'sent, ' + str(value.get('status') or 'no answer')
        if value.get('status') == 'ok':
            _set_cached_ti(ioc, ioc_type, name, key, value)
        else:
            # A failed explicit refresh invalidates an older success for that key.
            threat_intel_cache.pop(_ti_cache_key(ioc, ioc_type, name, key), None)
        return name, value

    sources = dict(await asyncio.gather(*(read_provider(*p) for p in providers)))

    verdict = "unknown"
    is_malicious = False
    is_suspicious = False
    has_data = False
    for src_name, src in sources.items():
        if src.get("status") != "ok":
            continue
        if src_name == "whois":
            # Registration data is context, not a reputation verdict: the
            # fact that RDAP answered says nothing about whether an IOC is
            # clean, so it never sets has_data. A domain registered days ago
            # is a real triage signal, though, so that much does count.
            if src.get("newly_registered"):
                is_suspicious = True
            continue
        if src_name == "virustotal":
            malicious, suspicious = src.get('malicious'), src.get('suspicious')
            if _ti_count(malicious) is not None and malicious > 0:
                is_malicious = True
            if _ti_count(suspicious) is not None and suspicious > 0:
                is_suspicious = True
            if _ti_count(malicious) is not None and _ti_count(suspicious) is not None and (src.get('total_engines') or 0) > 0:
                has_data = True
        if src_name == "abuseipdb":
            score = _ti_count(src.get("abuse_confidence_score"), 100)
            if score is None:
                continue
            has_data = True
            if score >= 75:
                is_malicious = True
            elif score >= 25:
                is_suspicious = True

    if is_malicious:
        verdict = "malicious"
    elif is_suspicious:
        verdict = "suspicious"
    elif has_data:
        verdict = "clean"

    successes = sum(s.get('status') == 'ok' for s in sources.values())
    return {"ioc": ioc, "type": ioc_type, "verdict": verdict, "sources": sources,
            "cached": bool(sources) and all(s.get('cached') for s in sources.values()),
            "lookup_status": 'complete' if successes and successes == len(sources) else 'partial' if successes else 'unavailable'}


def statistics_top_values_text(statistics_json: Optional[str]) -> str:
    """Return only statistic top values for IOC extraction.

    Query text, filters, index names, and field names are metadata rather than
    observed values. Excluding them prevents a domain/IP typed into a query
    from being treated as an IOC unless it also occurs in a result value.
    """
    if not statistics_json:
        return ""
    try:
        records = json.loads(statistics_json)
    except (json.JSONDecodeError, TypeError):
        return ""
    if not isinstance(records, list):
        records = [records]
    values = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for field_stat in record.get("fields") or []:
            if not isinstance(field_stat, dict):
                continue
            for top in field_stat.get("topValues") or []:
                value = top.get("value") if isinstance(top, dict) else None
                if value is not None and str(value).strip():
                    prefix = 'IMPHASH=' if str(field_stat.get('field', '')).upper() == 'IMPHASH' else ''
                    values.append(prefix + str(value))
    return "\n".join(values)


async def enrich_with_threat_intel(logs: List[str], analyst_data: Optional[str],
                                    virustotal_api_key: Optional[str],
                                    abuseipdb_api_key: Optional[str],
                                    internal_cidrs: Optional[List[str]] = None,
                                    internal_domains: Optional[List[str]] = None,
                                    enable_virustotal: bool = True,
                                    enable_abuseipdb: bool = True,
                                    enable_whois: bool = True,
                                    statistics_text: Optional[str] = None,
                                    blocked_values: Optional[List[str]] = None,
                                    forced_values: Optional[List[str]] = None) -> Tuple[str, List[Dict]]:
    """
    Extract IOCs from raw text, look each up (best-effort — a failed lookup
    never breaks the analysis), and return (context_text, findings).
    context_text is empty unless something notable (suspicious/malicious)
    was found, to keep the prompt from being padded with "clean" noise.
    """
    # One combined extraction gives logs, analyst context, and statistics a
    # shared `seen` set. An IOC present in both logs and top values is looked
    # up once, while statistics-only analyses still receive TI enrichment.
    combined_text = "\n".join(logs)
    if analyst_data:
        combined_text += "\n" + analyst_data
    statistic_values = statistics_top_values_text(statistics_text)
    if statistic_values:
        combined_text += "\n" + statistic_values
    custom_networks = _parse_custom_networks(internal_cidrs)
    custom_domains = _parse_custom_domains(internal_domains)
    iocs = extract_iocs(combined_text, custom_networks, custom_domains)

    flat: List[Tuple[str, str]] = []
    flat_seen = set()
    blocked_patterns = build_literal_matcher(blocked_values or (), forced_values or (), check_work)
    def blocked(value):
        return any(pattern is not None and next(pattern.finditer(value, check_work), None) is not None
                   for pattern in blocked_patterns)
    for t in ("ip", "domain", "hash", "url"):
        for value in iocs[t]:
            key = (t, _ti_identity(value, t))
            if blocked(value) or blocked(key[1]):
                continue
            if key in flat_seen:
                continue
            flat_seen.add(key)
            flat.append((value, t))
    flat = flat[:MAX_IOCS_TOTAL]

    # An import hash is not a whole-file MD5, despite having the same length.
    # Keep the observation visible without sending it to /files/{digest}.
    unsupported = {}
    if enable_virustotal and virustotal_api_key:
        for match in IMPHASH_PATTERN.finditer(combined_text):
            value = match[1].lower()
            if blocked(value) or blocked(match[1]) or len(unsupported) >= MAX_IOCS_PER_TYPE:
                continue
            unsupported[value] = {'ioc': value, 'type': 'hash', 'hash_algorithm': 'IMPHASH',
                'verdict': 'unknown', 'lookup_status': 'unavailable', 'cached': False,
                'sources': {'virustotal': {'status': 'unsupported',
                    'detail': 'IMPHASH describes imported functions, not a complete file digest. Automatic file-report lookup supports MD5, SHA-1 and SHA-256; no lookup was sent for this import hash.'}}}
    unsupported = list(unsupported.values())[:MAX_IOCS_TOTAL - len(flat)]

    if not flat:
        return "", unsupported

    findings = []
    skipped = 0
    deadline = asyncio.get_event_loop().time() + THREAT_INTEL_TIME_BUDGET_SECONDS
    async with httpx.AsyncClient() as client:
        for ioc, ioc_type in flat:
            # Enrichment is best-effort context, not the analysis itself —
            # never let a slow/rate-limited provider hold the whole request
            # hostage. Cached lookups cost nothing, so this budget only ever
            # trims fresh ones; the rest are enriched on a later run.
            remaining = deadline - asyncio.get_running_loop().time()
            try:
                result = await asyncio.wait_for(lookup_ioc(
                    client, ioc, ioc_type, virustotal_api_key, abuseipdb_api_key,
                    enable_virustotal=enable_virustotal,
                    enable_abuseipdb=enable_abuseipdb,
                    enable_whois=enable_whois,
                    timeout_seconds=max(0, remaining - 0.05)), timeout=max(0.05, remaining))
                if result.get("sources"):
                    findings.append(result)
                    skipped += any(s.get('status') == 'skipped' for s in result['sources'].values())
            except Exception as e:
                log.warning(f"Threat intel lookup failed for {ioc}: {e}")

    if skipped:
        log.warning(f"Threat intel budget ({THREAT_INTEL_TIME_BUDGET_SECONDS}s) reached — "
              f"skipped {skipped} uncached IOC(s); they'll be looked up on a later analysis.")

    _save_threat_intel_cache()
    findings.extend(unsupported)

    return build_threat_intel_context(findings), findings


def build_threat_intel_context(findings):
    """Render notable context from the same structured findings shown locally."""
    notable = [f for f in findings if f.get("verdict") in ("malicious", "suspicious")]
    if not notable:
        return ""

    lines = []
    for f in notable:
        icon = "🔴" if f["verdict"] == "malicious" else "⚠️"
        parts = []
        vt = f["sources"].get("virustotal")
        if vt and vt.get("status") == "ok" and vt.get('malicious') is not None:
            parts.append(f"VirusTotal {vt['malicious']}/{vt.get('total_engines', 0)} vendors flagged")
        abuse = f["sources"].get("abuseipdb")
        if abuse and abuse.get("status") == "ok":
            if abuse.get('abuse_confidence_score') is not None:
                parts.append(f"AbuseIPDB confidence {abuse['abuse_confidence_score']}%")
            if abuse.get('total_reports') is not None:
                parts.append(f"{abuse['total_reports']} reports in {abuse.get('report_window_days', 90)} days (AbuseIPDB)")
            facts = {k: abuse[k] for k in ('isp', 'usage_type', 'domain', 'country_name', 'country', 'last_reported_at') if abuse.get(k) is not None}
            if facts:
                parts.append('AbuseIPDB context: ' + json.dumps(facts, ensure_ascii=False))
        if vt and vt.get('status') == 'ok':
            facts = {k: vt[k] for k in ('asn', 'as_owner', 'network', 'country') if vt.get(k) is not None}
            if facts:
                parts.append('VirusTotal context: ' + json.dumps(facts, ensure_ascii=False))
        who = f["sources"].get("whois")
        if who and who.get("status") == "ok":
            if who.get("registered") is False:
                parts.append("no registration record (RDAP)")
            elif f["type"] == "domain":
                bits = []
                if who.get("age_days") is not None:
                    bits.append(f"registered {who['age_days']}d ago")
                if who.get("registrar"):
                    bits.append(f"via {who['registrar']}")
                if bits:
                    parts.append("WHOIS: " + ", ".join(bits))
            else:
                bits = [b for b in (who.get("org") or who.get("network_name"), who.get("country")) if b]
                if bits:
                    parts.append("WHOIS: " + ", ".join(str(b) for b in bits))
        lines.append(f"- {f['ioc']} ({f['type']}): {icon} {f['verdict'].capitalize()} — {'; '.join(parts)}")

    return "Threat Intelligence Findings:\n" + "\n".join(lines)


def build_prompt(logs: List[str], analyst_data: Optional[str], field_statistics: Optional[str], threat_intel_context: Optional[str],
                  custom_prompt: Optional[str], is_sanitized: bool, feedback_corrections=None) -> str:
    if custom_prompt and custom_prompt.strip():
        base = custom_prompt
        if is_sanitized:
            base = "**Note:** ⟦NAME#NUM⟧ are sanitized placeholders.\n\n" + base
    else:
        base = PROMPT_WITH_SANITIZATION if is_sanitized else PROMPT_NO_SANITIZATION
    
    # Lessons the analyst approved in Settings, shortened.
    recent = feedback_corrections if feedback_corrections is not None else [lesson[:100] for lesson in approved_lessons()]
    if recent:
        base += "\n\n[SYSTEM - DO NOT OUTPUT]\n"
        for correction in recent:
            base += f"• {correction[:100]}\n"
        base += "[END SYSTEM]\n"
    
    if logs:
        base += "\n\nSecurity Logs:\n```json\n" + "\n---\n".join(logs) + "\n```"
    else:
        base += "\n\nSecurity Logs:\nNo individual events were supplied; base the analysis on the aggregate statistics below."
    if analyst_data and analyst_data.strip():
        base += "\n\nAdditional Analyst Context:\n```text\n" + analyst_data.strip() + "\n```"
    if field_statistics and field_statistics.strip():
        base += ("\n\nSearch Field Statistics (aggregate evidence, not individual events):\n"
                 "Use counts and percentages as statistical context and do not describe them as raw log records.\n"
                 "```json\n" + field_statistics.strip() + "\n```")
    if threat_intel_context and threat_intel_context.strip():
        base += "\n\n" + threat_intel_context.strip()
    return base


# ============== ENDPOINTS ==============

@app.post("/defang")
async def defang_endpoint(request: DefangRequest):
    return {"original": request.text, "defanged": defang_text(request.text)}


@app.post("/refang")
async def refang_endpoint(request: RefangRequest):
    return {"original": request.text, "refanged": refang_text(request.text)}


# ---- Indicators of a case ----
# Every IP, domain, URL, hash, email, user, host and SID found in the case's
# logs, for the popup's Indicators list. Local only: nothing is sent anywhere.
# Public IPs, domains, URLs and hashes come from the threat-intelligence
# extraction and can be checked; internal addresses, users, hosts and SIDs
# come from the privacy detection and are listed for reference.
MAX_INDICATORS = 500
INDICATOR_ORDER = ["ip", "domain", "url", "hash", "email", "user", "host", "sid"]
PRIVACY_INDICATOR_TYPES = {"USER": "user", "HOST": "host", "EMAIL": "email", "IP_INT": "ip", "IP_EXT": "ip",
                           "DOMAIN": "domain", "SID": "sid"}


def collect_indicators(logs: List[str], internal_cidrs=None, internal_domains=None) -> List[Dict]:
    check_work()
    networks = _parse_custom_networks(internal_cidrs)
    domains = _parse_custom_domains(internal_domains)
    text = "\n".join(logs)
    found: Dict[str, Dict] = {}

    def add(value, kind, internal, checkable):
        value = str(value).strip()
        if not value or value in found or len(found) >= MAX_INDICATORS:
            return
        found[value] = {"value": value, "type": kind, "scope": "internal" if internal else "public", "checkable": checkable}

    public = extract_iocs(text, networks, domains)
    for kind in ("ip", "domain", "url", "hash"):
        for value in public.get(kind, []):
            add(value, kind, False, True)
    # The privacy detection also finds users, hosts and internal addresses.
    context = _new_privacy_context(logs)
    _, mapping = sanitize_logs(logs, True, None, None, internal_cidrs, None, None, context)
    for marker, value in mapping.items():
        category = re.match(r"⟦([A-Z_]+)#", marker)
        kind = PRIVACY_INDICATOR_TYPES.get(category.group(1)) if category else None
        if not kind:
            continue
        if kind == "ip":
            internal = is_internal_ip(value, networks)
        elif kind in ("domain", "host"):
            internal = is_internal_domain(value, domains) or kind == "host"
        else:
            internal = kind != "email"
        add(value, kind, internal, False)
    for item in found.values():
        check_work()
        item["count"] = max(1, text.count(item["value"]))
    return sorted(found.values(), key=lambda item: (INDICATOR_ORDER.index(item["type"]), item["scope"] != "public", item["value"].lower()))


@app.post("/indicators")
async def indicators_endpoint(request: IndicatorRequest):
    logs = [log for log in request.logs if isinstance(log, str) and log.strip()]
    items = await local_work(collect_indicators, logs, request.internal_cidrs, request.internal_domains)
    return {"indicators": items, "limited": len(items) >= MAX_INDICATORS}


@app.post("/sanitize")
async def sanitize_endpoint(request: SanitizationRequest):
    inputs = list(request.logs) + ([request.analyst_data] if request.analyst_data else [])
    protected, secret_mapping, secret_findings = await local_work(protect_secret_inputs,
        inputs, request.allowed_ambiguous_secrets, request.force_hide_values, request.secret_protection.model_dump(), None, request.custom_regex_rules, request.heuristic_field_exclusions, request.heuristic_settings)
    privacy_context = await local_work(_new_privacy_context, protected, secret_mapping)
    sanitized_logs, mapping = await local_work(sanitize_logs,
        protected,
        request.enable_pattern_sanitization,
        request.custom_keywords,
        request.json_keys_to_hide,
        request.internal_cidrs,
        request.statistics_fields_to_hide,
        request.custom_regex_rules, privacy_context
    )
    analyst = sanitized_logs[len(request.logs)] if request.analyst_data else None
    sanitized_logs = sanitized_logs[:len(request.logs)]
    return {"sanitized_logs": sanitized_logs, "sanitized_analyst_data": analyst, "mapping_table": public_mapping(mapping, secret_mapping),
            "secret_findings": public_secret_findings(secret_findings),
            "sanitized_log": ("\n\n" if request.output_mode == 'raw_request' else LOG_SEPARATOR).join(sanitized_logs)}


@app.post("/secrets/scan")
async def secret_scan_endpoint(request: SecretScanRequest):
    """Local preflight used by the compact per-request review UI."""
    try:
        started = time.perf_counter()
        def scan():
            raw = [dict(f.public(), source_index=i) for i, text in enumerate(request.texts)
                   for f in scan_secrets(text, request.secret_protection.model_dump(), request.heuristic_field_exclusions, request.heuristic_settings, request.custom_regex_rules)]
            strong_values = {item["value"] for item in raw if item["confidence"] == "high"}
            counts = Counter(item["value"] for item in raw)
            for item in raw:
                item["occurrence_count"] = counts[item["value"]]
                if item["confidence"] != "high" and item["value"] in strong_values:
                    item["confidence"] = "high"
                    item["reason"] = "same logical value as a high-confidence credential in this request"
            return raw
        findings = await local_work(scan)
        return {"findings": findings, "timings_ms": {"detection": (time.perf_counter()-started)*1000}}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, "Secret scan could not complete; outbound sending stopped.") from exc



def _failed_with_record(job, error: HTTPException):
    """An error reply that still says what was sent before the failure."""
    outbound = job.get('outbound') or _new_outbound()
    if outbound.get('ai') and outbound['ai'].get('outcome') == 'sent':
        outbound['ai']['outcome'] = 'failed: ' + str(error.detail)[:200]
    if not outbound.get('ai') and not outbound.get('lookups'):
        raise error
    return JSONResponse(status_code=error.status_code, content={"detail": error.detail, "outbound": outbound})


@app.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_logs(request: LogAnalysisRequest, connection: Request = None):
    if request.request_id in _cancelled_analyses:
        raise HTTPException(499, "Analysis cancelled; nothing was sent.")
    job = {"phase": "Sanitizing logs", "timings_ms": {}, "task": asyncio.current_task(), "outbound": _new_outbound()}
    request_id = request.request_id
    # Status lives only in memory and contains timings, never content or maps.
    if request_id:
        if request_id in _analysis_jobs and _analysis_jobs[request_id].get('task'):
            raise HTTPException(409, "Analysis already running")
        _analysis_jobs[request_id] = job
    token = _job_context.set(job)
    try:
        if connection is None:
            result = await _analyze_logs(request)
        else:
            work = asyncio.create_task(_analyze_logs(request))
            try:
                while not work.done():
                    await asyncio.wait({work}, timeout=0.1)
                    if await connection.is_disconnected():
                        raise asyncio.CancelledError()
                result = await work
            finally:
                if not work.done():
                    work.cancel()
                    await asyncio.gather(work, return_exceptions=True)
        result.timings_ms = dict(job['timings_ms'])
        result.outbound = job['outbound']
        job['phase'] = 'Complete'
        return result
    except asyncio.CancelledError:
        job['phase'] = 'Cancelled'
        return _failed_with_record(job, HTTPException(499, "Analysis cancelled; no further requests will be sent."))
    except HTTPException as error:
        job['phase'] = 'Failed'
        return _failed_with_record(job, error)
    except Exception:
        job['phase'] = 'Failed'
        raise
    finally:
        job['task'] = None
        _job_context.reset(token)
        if request_id:
            asyncio.get_running_loop().call_later(60, _analysis_jobs.pop, request_id, None)


async def _analyze_logs(request: LogAnalysisRequest):
    if not request.logs and not request.field_statistics:
        raise HTTPException(status_code=400, detail="No logs or field statistics provided")
    
    log.debug(f"Analysis request: mode={request.mode}, sanitize={request.sanitize}, pattern={request.enable_pattern_sanitization}")
    
    if request.mode == "sanitize_only":
        inputs = list(request.logs)
        has_analyst_data = bool(request.analyst_data and request.analyst_data.strip())
        if has_analyst_data:
            inputs.append(request.analyst_data.strip())
        statistics_json = json.dumps(request.field_statistics, ensure_ascii=False) if request.field_statistics else None
        if statistics_json:
            inputs.append(statistics_json)

        protected_inputs, secret_mapping, secret_findings = await local_work(protect_secret_inputs,
            inputs, request.allowed_ambiguous_secrets, request.force_hide_values, request.secret_protection.model_dump(), None, request.custom_regex_rules, request.heuristic_field_exclusions, request.heuristic_settings)
        privacy_context = await local_work(_new_privacy_context, protected_inputs, secret_mapping)
        sanitized_inputs, mapping = await local_work(sanitize_logs,
            protected_inputs,
            request.enable_pattern_sanitization,
            request.custom_keywords,
            request.json_keys_to_hide,
            request.internal_cidrs,
            request.statistics_fields_to_hide,
            request.custom_regex_rules, privacy_context
        )
        sanitized_logs = sanitized_inputs[:len(request.logs)]
        offset = len(request.logs)
        sanitized_analyst_data = sanitized_inputs[offset] if has_analyst_data else None
        offset += 1 if has_analyst_data else 0
        sanitized_statistics = sanitized_inputs[offset] if statistics_json else None

        output_parts = list(sanitized_logs)
        if sanitized_statistics:
            output_parts.append(sanitized_statistics)

        return LogAnalysisResponse(
            analysis="[Sanitization completed]",
            timestamp=datetime.now().isoformat(),
            sanitized_log=("\n\n" if request.output_mode == 'raw_request' else LOG_SEPARATOR).join(output_parts),
            sanitized_analyst_data=sanitized_analyst_data,
            sanitized_field_statistics=sanitized_statistics,
            threat_intel_status={"state": "local_only", "message": "Sanitize-only mode is local. Choose AI analysis and enable Threat intelligence to run lookups."},
            mapping_table=public_mapping(mapping, secret_mapping),
            secret_findings=public_secret_findings(secret_findings)
        )
    
    try:
        # Enabled protections run before IOC extraction, including edited input.
        initial = list(request.logs)
        has_analyst = bool(request.analyst_data and request.analyst_data.strip())
        if has_analyst:
            initial.append(request.analyst_data.strip())
        statistics_json = json.dumps(request.field_statistics, ensure_ascii=False) if request.field_statistics else None
        if statistics_json:
            initial.append(statistics_json)
        has_custom_prompt = bool(request.custom_prompt and request.custom_prompt.strip())
        if has_custom_prompt:
            initial.append(request.custom_prompt.strip())
        # Feedback participates in classification and marker reservation before
        # any current value is granted restoration eligibility. Scan its full
        # stored correction before the prompt's display-length truncation.
        raw_feedback = approved_lessons()
        all_initial = initial + raw_feedback
        protected_all, secret_mapping, secret_findings = await local_work(protect_secret_inputs,
            all_initial, request.allowed_ambiguous_secrets, request.force_hide_values, request.secret_protection.model_dump(), None, request.custom_regex_rules, request.heuristic_field_exclusions, request.heuristic_settings)
        # TI has its own outbound policy: credentials and explicit hides are
        # blocked, but automatic AI privacy masking must not erase public IOCs.
        # Keep the credential-protected source, never restore privacy mappings
        # to reconstruct a provider request. Feedback/custom prompts aren't IOCs.
        ti_source_count = len(request.logs) + int(has_analyst) + int(bool(statistics_json))
        credential_protected_ti_sources = protected_all[:ti_source_count]
        # Explicit privacy Hide is outbound policy, not an optional automatic
        # privacy feature. One request-local context also prevents feedback and
        # logs from receiving the same marker for different originals.
        privacy_context = await local_work(_new_privacy_context, protected_all, secret_mapping)
        protected_all, mapping = await local_work(
            sanitize_logs, protected_all,
            request.enable_pattern_sanitization if request.sanitize else False,
            request.custom_keywords if request.sanitize else None,
            request.json_keys_to_hide if request.sanitize else None,
            request.internal_cidrs,
            request.statistics_fields_to_hide if request.sanitize else None,
            request.custom_regex_rules, privacy_context)
        protected_initial = protected_all[:len(initial)]
        protected_feedback = protected_all[len(initial):]
        protected_logs = protected_initial[:len(request.logs)]
        offset = len(request.logs)
        protected_analyst = protected_initial[offset] if has_analyst else None
        offset += 1 if has_analyst else 0
        protected_statistics = protected_initial[offset] if statistics_json else None
        offset += 1 if statistics_json else 0
        protected_custom_prompt = protected_initial[offset] if has_custom_prompt else None

        threat_intel_context = ""
        threat_intel_findings = None
        ti_hash_groups = []
        threat_intel_status = {"state": "disabled", "message": "Threat intelligence was off for this analysis. Enable it and analyze again to check eligible public indicators."}
        ti_configured = bool((request.enable_virustotal and request.virustotal_api_key)
                             or (request.enable_abuseipdb and request.abuseipdb_api_key)
                             or request.enable_whois)
        if request.enable_threat_intel and not ti_configured:
            threat_intel_status = {"state": "not_configured", "message": "No lookup source is ready. Enable WHOIS / RDAP, or enable VirusTotal or AbuseIPDB and add its API key in Settings."}
        if request.enable_threat_intel and ti_configured:
            analysis_phase("Checking threat intelligence")
            ti_started = time.perf_counter()
            try:
                # Apply the same explicit rules to the credential-protected
                # source. Automatic patterns apply only to the AI view above.
                # The temporary context is discarded, not merged into Changes.
                ti_privacy_context = await local_work(_new_privacy_context, credential_protected_ti_sources, secret_mapping)
                ti_sanitized, _ = await local_work(
                    sanitize_logs, credential_protected_ti_sources, False,
                    request.custom_keywords if request.sanitize else None,
                    request.json_keys_to_hide if request.sanitize else None,
                    request.internal_cidrs,
                    request.statistics_fields_to_hide if request.sanitize else None,
                    request.custom_regex_rules, ti_privacy_context)
                ti_logs = ti_sanitized[:len(protected_logs)]
                ti_offset = len(protected_logs)
                ti_analyst = ti_sanitized[ti_offset] if protected_analyst else None
                ti_offset += 1 if protected_analyst else 0
                ti_statistics = ti_sanitized[ti_offset] if protected_statistics else None
                threat_intel_context, threat_intel_findings = await asyncio.wait_for(enrich_with_threat_intel(
                    ti_logs, ti_analyst,
                    request.virustotal_api_key, request.abuseipdb_api_key,
                    request.internal_cidrs, request.internal_domains,
                    enable_virustotal=request.enable_virustotal,
                    enable_abuseipdb=request.enable_abuseipdb,
                    enable_whois=request.enable_whois,
                    statistics_text=ti_statistics,
                    blocked_values=list(secret_mapping.values()), forced_values=request.force_hide_values
                ), timeout=THREAT_INTEL_TIME_BUDGET_SECONDS + 0.1)
                if not threat_intel_findings:
                    threat_intel_status = {"state": "no_results", "message": "No eligible indicators produced a lookup. Private/internal addresses, configured internal domains, credentials and explicitly hidden values are excluded. The selected services must support the indicator type."}
                else:
                    sources = [source for finding in threat_intel_findings
                               for source in finding.get('sources', {}).values()]
                    successful = sum(source.get('status') == 'ok' for source in sources)
                    state = 'complete' if sources and successful == len(sources) else 'partial' if successful else 'unavailable'
                    message = ("Lookup results are available below." if state == 'complete' else
                               "Some lookup sources are unavailable. Review the service details below." if state == 'partial' else
                               "Lookup services returned no usable data. Review sign-in, quota and service errors below.")
                    if sources and all(source.get('status') == 'unsupported' for source in sources):
                        state, message = 'not_queried', 'These indicators do not support automatic lookup. See the explanation below; no provider request was made.'
                    elif any(source.get('status') == 'unsupported' for source in sources):
                        message = 'Some indicators were not queried. Review the lookup results and explanations below.'
                    threat_intel_status = {"state": state, "message": message, "indicators": len(threat_intel_findings)}
            except HTTPException:
                raise
            except Exception as e:
                log.warning("Threat intel enrichment unavailable or timed out")
                threat_intel_status = {"state": "unavailable", "message": "Threat intelligence could not complete or timed out. Analysis continued without enrichment; try again or check the lookup services."}
            finally:
                _job_context.get()["timings_ms"]["threat_intelligence"] = (time.perf_counter()-ti_started)*1000

        analysis_phase("Sanitizing logs")
        # Scan TI content before optional privacy masking can alter its syntax.
        if threat_intel_context or threat_intel_findings:
            # Protect structured facts first, then derive prose from them. A
            # second heuristic pass on prose loses the provider field context.
            ti_inputs = [json.dumps(threat_intel_findings, ensure_ascii=False) if threat_intel_findings
                         else threat_intel_context or ""]
            ti_exclusions = list(request.heuristic_field_exclusions or ())
            if threat_intel_findings:
                ti_exclusions.extend(TI_METADATA_PATHS)
            ti_hash_groups = await local_work(_ti_hash_identity_groups, threat_intel_findings,
                credential_protected_ti_sources + ti_inputs + list(secret_mapping.values()))
            ti_allowed = set(request.allowed_ambiguous_secrets or ())
            for group in ti_hash_groups:
                ti_allowed.update(group)
            ti_protected, _, ti_findings = await local_work(
                protect_secret_inputs, ti_inputs, ti_allowed,
                request.force_hide_values, request.secret_protection.model_dump(), secret_mapping, request.custom_regex_rules,
                ti_exclusions, request.heuristic_settings, equivalent_values=ti_hash_groups)
            if threat_intel_findings:
                threat_intel_findings = json.loads(ti_protected[0])
                threat_intel_context = await local_work(build_threat_intel_context, threat_intel_findings)
            else:
                threat_intel_context = ti_protected[0]
            secret_findings.extend(ti_findings)
            upgraded = await local_work(_revoke_restoration_for_secrets,
                privacy_context, secret_mapping,
                protected_logs + ([protected_analyst] if protected_analyst else [])
                + ([protected_statistics] if protected_statistics else [])
                + ([protected_custom_prompt] if protected_custom_prompt else [])
                + protected_feedback + [threat_intel_context], ti_hash_groups)
            cursor = 0
            protected_logs = upgraded[:len(protected_logs)]; cursor += len(protected_logs)
            if protected_analyst: protected_analyst = upgraded[cursor]; cursor += 1
            if protected_statistics: protected_statistics = upgraded[cursor]; cursor += 1
            if protected_custom_prompt: protected_custom_prompt = upgraded[cursor]; cursor += 1
            protected_feedback = upgraded[cursor:cursor + len(protected_feedback)]; cursor += len(protected_feedback)
            threat_intel_context = upgraded[cursor]
            sanitized_ti, mapping = await local_work(
                sanitize_logs, [threat_intel_context],
                request.enable_pattern_sanitization if request.sanitize else False,
                request.custom_keywords if request.sanitize else None,
                request.json_keys_to_hide if request.sanitize else None,
                request.internal_cidrs, None, request.custom_regex_rules,
                privacy_context)
            threat_intel_context = sanitized_ti[0]

        logs_for_ai = protected_logs
        analyst_data_for_ai = protected_analyst
        statistics_for_ai = protected_statistics
        ti_context_for_ai = threat_intel_context or None
        is_sanitized = bool(mapping)

        log.info(f"Sanitized {len(mapping)} values")

        # Propagate evidence learned from TI while each source still has its
        # JSON key/type context. Repeating known-value matching on the assembled
        # prose would incorrectly hide JSON keys that happen to equal a value.
        final_config = request.secret_protection.model_dump()
        final_config["heuristics"] = False
        final_sources = logs_for_ai + [analyst_data_for_ai or '', statistics_for_ai or '',
                                      protected_custom_prompt or '', ti_context_for_ai or ''] + protected_feedback
        checked_sources, _, source_findings = await local_work(
            protect_secret_inputs, final_sources, request.allowed_ambiguous_secrets,
            request.force_hide_values, final_config, secret_mapping, None,
            request.heuristic_field_exclusions, request.heuristic_settings,
            equivalent_values=ti_hash_groups)
        secret_findings.extend(source_findings)
        upgraded = await local_work(_revoke_restoration_for_secrets,
            privacy_context, secret_mapping, checked_sources, ti_hash_groups)
        cursor = len(logs_for_ai)
        logs_for_ai = upgraded[:cursor]
        analyst_data_for_ai, statistics_for_ai, protected_custom_prompt, ti_context_for_ai = (
            value or None for value in upgraded[cursor:cursor + 4])
        protected_feedback = upgraded[cursor + 4:]

        # Build prompt. Feedback was already classified and sanitized in the
        # same request context above; build_prompt applies its display limit.
        prompt = build_prompt(logs_for_ai, analyst_data_for_ai, statistics_for_ai, ti_context_for_ai,
                              protected_custom_prompt, is_sanitized or bool(secret_mapping), protected_feedback)
        # Fail closed immediately before every AI provider path. Placeholders
        # themselves do not match credential rules. Generic heuristics already
        # ran with source-field provenance; rerunning them on the assembled
        # prose would discard scoped exclusions and recreate metadata noise.
        checked, final_secret_mapping, final_findings = await local_work(
            protect_secret_inputs, [prompt], request.allowed_ambiguous_secrets,
            request.force_hide_values, final_config, None, None,
            request.heuristic_field_exclusions, request.heuristic_settings,
            secret_mapping.keys(), equivalent_values=ti_hash_groups)
        secret_mapping.update(final_secret_mapping)
        secret_findings.extend(final_findings)
        # Even evidence discovered by the last boundary check revokes local
        # restoration and public mappings before the model response is used.
        upgraded = await local_work(_revoke_restoration_for_secrets,
            privacy_context, secret_mapping,
            checked + logs_for_ai + [analyst_data_for_ai or '', statistics_for_ai or ''], ti_hash_groups)
        prompt = upgraded[0]
        logs_for_ai = upgraded[1:1 + len(logs_for_ai)]
        analyst_data_for_ai = upgraded[-2] or None
        statistics_for_ai = upgraded[-1] or None
        analysis_phase("Waiting for AI")
        ai_started = time.perf_counter()

        ai_funcs = {
            "groq": call_groq_ai,
            "deepseek": call_deepseek_ai,
            "together": call_together_ai,
            "gemini": call_gemini_ai,
            "claude": call_claude_ai
        }
        
        if request.mode == "custom" and request.custom_provider:
            config = request.custom_provider
            sent = _record_ai_request(config.name or "Custom model", config.model,
                                      config.endpoint.replace("{model}", quote(config.model.removeprefix("models/"), safe="")), prompt)
        elif request.mode == "openrouter" and request.api_key and (request.openrouter_model or "").strip():
            sent = _record_ai_request("OpenRouter", request.openrouter_model.strip(), f"{OPENROUTER_API}/chat/completions", prompt)
        elif request.mode in AI_PROVIDERS and request.api_key and (request.model or "").strip():
            model = request.model.strip()
            sent = _record_ai_request(AI_PROVIDERS[request.mode][0], model, provider_endpoint(request.mode, model), prompt)
        else:
            sent = None

        if request.mode == "custom":
            if not request.custom_provider:
                raise HTTPException(status_code=400,
                                    detail="Custom model selected but its configuration was not sent.")
            # No API-key requirement here: local runners (Ollama, LM Studio,
            # vLLM) legitimately have none.
            analysis = await asyncio.wait_for(call_custom_ai(prompt, request.api_key, request.custom_provider), AI_TIMEOUT_SECONDS)
        elif request.mode == "openrouter":
            if not request.api_key:
                raise HTTPException(status_code=400, detail="openrouter API key required")
            if not (request.openrouter_model or "").strip():
                raise HTTPException(status_code=400, detail="Choose an OpenRouter model in Settings → AI models (Find free models), "
                                                            "or paste a model ID.")
            analysis = await asyncio.wait_for(call_openrouter_ai(prompt, request.api_key, request.openrouter_model.strip(), request.generation), AI_TIMEOUT_SECONDS)
        else:
            if request.mode not in ai_funcs:
                raise HTTPException(status_code=400, detail=f"Unknown mode: {request.mode}")

            if not request.api_key:
                raise HTTPException(status_code=400, detail=f"{request.mode} API key required")

            # The chosen model is passed only when there is one; the provider call
            # refuses to run without it (chosen_model), so nothing is sent.
            model_argument = {"model": request.model.strip()} if (request.model or "").strip() else {}
            if request.generation:
                model_argument["generation"] = request.generation
            analysis = await asyncio.wait_for(ai_funcs[request.mode](prompt, request.api_key, **model_argument), AI_TIMEOUT_SECONDS)
        _job_context.get()["timings_ms"]["ai"] = (time.perf_counter()-ai_started)*1000
        if sent:
            sent["outcome"] = "answered (cut off at the output limit)" if _job_context.get().get("answer_cut_off") else "answered"
        
        if is_sanitized and mapping:
            analysis = replace_placeholders(analysis, mapping, privacy_context)

        # Secret placeholders intentionally remain masked in the report.
        # Privacy mappings are intentionally restorable. Credential mappings
        # are not returned: exposing them would defeat secret masking and make
        # browser/session persistence of the response unnecessarily risky.
        combined_mapping = public_mapping(mapping, secret_mapping)
        
        return LogAnalysisResponse(
            analysis=analysis,
            timestamp=datetime.now().isoformat(),
            sanitized_log=(("\n\n" if request.output_mode == 'raw_request' else LOG_SEPARATOR).join(logs_for_ai)) if (is_sanitized or secret_mapping) else None,
            sanitized_analyst_data=analyst_data_for_ai if (is_sanitized or secret_mapping) and analyst_data_for_ai else None,
            sanitized_field_statistics=statistics_for_ai,
            mapping_table=combined_mapping or None,
            threat_intel_findings=threat_intel_findings,
            threat_intel_status=threat_intel_status,
            secret_findings=public_secret_findings(secret_findings)
        )
    
    except HTTPException:
        raise
    except asyncio.TimeoutError:
        raise HTTPException(504, "AI request timed out. Retry or select another provider.")
    except Exception as e:
        log.warning(f"Analysis failed: {type(e).__name__}")
        raise HTTPException(status_code=500, detail=public_error(e))


@app.post("/threat-intel/lookup")
async def threat_intel_lookup_endpoint(request: ThreatIntelLookupRequest):
    """On-demand single-IOC reputation check (e.g. a 'Check IOC' box in the popup),
    independent of the auto-enrichment that runs during /analyze."""
    try:
        findings = await local_work(scan_secrets, request.ioc, request.secret_protection.model_dump(),
                                    request.heuristic_field_exclusions, request.heuristic_settings, request.custom_regex_rules)
        privacy_hidden, _ = await local_work(
            sanitize_logs, [request.ioc], False, None, None, None, None,
            request.custom_regex_rules)
        allowed = set(request.allowed_ambiguous_secrets or ()) - set(request.force_hide_values or ())
        if privacy_hidden[0] != request.ioc or any(f.confidence == 'high' or f.value not in allowed for f in findings) or any(v and v in request.ioc for v in (request.force_hide_values or [])):
            raise HTTPException(status_code=400, detail="Credential-like values cannot be sent to threat-intelligence services.")
    except HTTPException:
        raise
    except Exception as exc:
        log.warning(f"Secret scan before a lookup failed: {type(exc).__name__}")
        raise HTTPException(status_code=500, detail="Secret scan could not complete; threat-intelligence sending stopped: "
                            + public_error(exc))
    ioc = request.ioc.strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="No IOC provided")

    ioc_type = request.ioc_type or detect_ioc_type(ioc)
    if not ioc_type:
        raise HTTPException(status_code=400, detail="Could not determine IOC type (ip/domain/url/hash) — specify ioc_type explicitly.")

    try:
        ioc = _ti_identity(ioc, ioc_type)
        if ioc_type == 'domain':
            valid = GENERIC_DOMAIN_PATTERN.fullmatch(ioc)
        else:
            valid = detect_ioc_type(ioc) == ioc_type
        if not valid:
            raise ValueError('Invalid indicator')
    except (ValueError, UnicodeError):
        raise HTTPException(status_code=400, detail="This value does not match the selected indicator type.")

    if not ((request.enable_virustotal and request.virustotal_api_key)
            or (request.enable_abuseipdb and request.abuseipdb_api_key and ioc_type == 'ip')
            or (request.enable_whois and ioc_type in ('ip', 'domain'))):
        raise HTTPException(status_code=400, detail="No enabled source can check this value. Enable WHOIS for IPs/domains, or add a key for an applicable reputation source in Settings.")

    # The lookups are recorded like an analysis's, so the popup can add them
    # to the case's record of what was sent.
    job = {"phase": "Checking indicator", "timings_ms": {}, "outbound": _new_outbound()}
    token = _job_context.set(job)
    try:
        async with httpx.AsyncClient() as client:
            result = await lookup_ioc(
                client, ioc, ioc_type, request.virustotal_api_key, request.abuseipdb_api_key,
                use_cache=request.use_cache,
                enable_virustotal=request.enable_virustotal,
                enable_abuseipdb=request.enable_abuseipdb,
                enable_whois=request.enable_whois)
    finally:
        _job_context.reset(token)
    result = {**result, "outbound": job["outbound"]}

    _save_threat_intel_cache()
    return result


def _custom_provider_error(response):
    """Read provider errors without displaying their entire JSON envelope."""
    try:
        data = response.json()
    except ValueError:
        data = None
    error = data.get("error", data) if isinstance(data, dict) else None
    if isinstance(error, dict):
        message = error.get("message") or error.get("detail")
        return (str(message)[:600] if message else f"Service returned HTTP {response.status_code}",
                str(error.get("param") or ""), str(error.get("code") or ""))
    if isinstance(error, str):
        return error[:600], "", ""
    return f"Service returned HTTP {response.status_code}. Check the service URL and connection type.", "", ""


def _adjust_custom_request(response, payload, fmt):
    """Only adapt explicitly rejected parameters; never retry unrelated failures.

    Each adjustment removes its original key, so it can run at most once. The
    response cap, model, endpoint and already-protected prompt remain unchanged.
    """
    if response.status_code not in (400, 422):
        return False
    message, param, code = _custom_provider_error(response)
    unsupported = re.search(r"deprecated|unsupported|not supported|does not support|not allowed|unrecognized|unknown parameter", message, re.I)
    settings = payload.get("generationConfig", payload)
    if "temperature" in settings and (
        (re.search(r"\btemperature\b", message, re.I) and unsupported)
        or (param == "temperature" and code in ("unsupported_parameter", "unsupported_value"))
    ):
        del settings["temperature"]
        return True
    if fmt == "openai" and "max_tokens" in payload and "max_completion_tokens" in message and (
        (re.search(r"\bmax_tokens\b", message) and unsupported)
        or (param == "max_tokens" and code == "unsupported_parameter")
    ):
        payload["max_completion_tokens"] = payload.pop("max_tokens")
        return True
    return False


def _custom_answer(data):
    def visible(value):
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return "".join(block["text"] for block in value
                if isinstance(block, dict) and not block.get("thought")
                and block.get("type", "text") in ("text", "output_text")
                and isinstance(block.get("text"), str))
        return ""
    if not isinstance(data, dict):
        return ""
    for path in ("choices.0.message.content", "content", "candidates.0.content.parts", "choices.0.text", "message.content"):
        text = _without_thinking(visible(_resolve_path(data, path)))
        if text.strip():
            return text
    return ""


async def call_custom_ai(prompt: str, api_key: Optional[str], config: "CustomProviderConfig") -> str:
    """Format-based custom services, with optional tuning and bounded compatibility.

    Default temperature is omitted. Older saved profiles can still request one;
    if the service explicitly rejects it, retry using that model's default.
    """
    fmt = config.api_format
    label = config.name or "Custom model"
    headers = {"Content-Type": "application/json"}
    if config.extra_headers:
        headers.update(config.extra_headers)
    if fmt == "anthropic":
        if api_key:
            headers["x-api-key"] = api_key
        headers.setdefault("anthropic-version", "2023-06-01")
        payload = {"model": config.model, "max_tokens": config.max_tokens,
                   "messages": [{"role": "user", "content": prompt}]}
    elif fmt == "gemini":
        # In a header rather than the address, so proxies and server logs that
        # record addresses never see the key.
        if api_key:
            headers["x-goog-api-key"] = api_key
        payload = {"contents": [{"parts": [{"text": prompt}]}],
                   "generationConfig": {"maxOutputTokens": config.max_tokens}}
    else:
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {"model": config.model, "max_tokens": config.max_tokens,
                   "messages": [{"role": "user", "content": prompt}]}
    if config.temperature is not None:
        payload.get("generationConfig", payload)["temperature"] = config.temperature

    try:
        # Gemini embeds its model in the URL. Explicit templates also work for
        # company gateways; encode the model as one path component.
        url = checked_destination(config.endpoint.replace("{model}", quote(config.model.removeprefix("models/"), safe="")),
                                  f"{label}: the service URL", allow_userinfo=True)
        # One deadline covers all attempts, including a compatibility retry.
        async with asyncio.timeout(config.timeout_seconds):
            async with httpx.AsyncClient(timeout=config.timeout_seconds, follow_redirects=False) as client:
                for attempt in range(3):
                    response = await client.post(url, headers=headers, json=payload)
                    if response.status_code == 200 or attempt == 2 or not _adjust_custom_request(response, payload, fmt):
                        break
    except (httpx.TimeoutException, asyncio.TimeoutError):
        raise HTTPException(504, f"{label}: the service took too long to reply. Try again or choose another model.")
    except DestinationError as exc:
        if " is refused: " in str(exc):
            raise HTTPException(400, str(exc))
        raise HTTPException(400, f"{label}: enter a complete service URL starting with http:// or https://.")
    except (httpx.InvalidURL, httpx.UnsupportedProtocol):
        raise HTTPException(400, f"{label}: enter a complete service URL starting with http:// or https://.")
    except httpx.RequestError:
        raise HTTPException(502, f"{label}: cannot reach the model service. Check its address and that the server is running.")

    if response.status_code != 200:
        message, _, _ = _custom_provider_error(response)
        if api_key:
            message = message.replace(api_key, "[hidden]")
        help_text = {401: "Check the API key.", 403: "Check the key's access to this model.",
                     404: "Check the model ID and service URL.",
                     429: "Check the service's usage limits or try again later."}.get(response.status_code, "")
        raise HTTPException(response.status_code, f"{label}: {message} {help_text}".strip())
    try:
        data = response.json()
    except ValueError:
        raise HTTPException(502, f"{label}: the service did not return JSON. Check the service URL and connection type.")
    return usable_answer(label, _custom_answer(data), answer_parts(fmt, data)[1], config.max_tokens,
                         "the Response length limit (Settings → Your AI models)")


# Built-in providers: name and chat endpoint ({model} is filled for Gemini).
# The model is always the analyst's choice from the provider's own model list
# (/providers/{provider}/models); none is built in, because providers retire
# model IDs and a fixed one eventually fails for everyone.
AI_PROVIDERS = {
    "groq": ("Groq", "https://api.groq.com/openai/v1/chat/completions"),
    "deepseek": ("DeepSeek", "https://api.deepseek.com/v1/chat/completions"),
    "together": ("Together AI", "https://api.together.xyz/v1/chat/completions"),
    "gemini": ("Gemini", "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"),
    "claude": ("Claude", "https://api.anthropic.com/v1/messages"),
}
MODEL_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}")
# What providers say when a model is retired, renamed or not open to the key.
_MODEL_UNAVAILABLE = re.compile(
    r"model_not_found|model[^.\n]{0,120}(does not exist|not found|not exist|decommissioned|deprecated|no longer|"
    r"not supported|not available|unknown|invalid|retired|access)|unknown model|no such model|not_found_error",
    re.IGNORECASE)


_OUTPUT_LIMIT_PARAMETER = re.compile(r"max_completion_tokens|max_tokens|max_output_tokens|maxOutputTokens", re.IGNORECASE)
# Reasoning models spend part of the output on thinking before they answer
# (DeepSeek, Gemini and Claude count it in the same limit), so the old 4,000
# left long prompts with no answer. Settings can lower or raise this, and the
# extension caps it at the maximum the provider reports for the model.
DEFAULT_MAX_OUTPUT_TOKENS = 16384


def output_limit(generation: Optional[GenerationSettings]) -> int:
    return (generation.max_output_tokens if generation else None) or DEFAULT_MAX_OUTPUT_TOKENS


def provider_endpoint(mode: str, model: str) -> str:
    return AI_PROVIDERS[mode][1].replace("{model}", quote(model.removeprefix("models/"), safe=""))


def chosen_model(mode: str, model: Optional[str]) -> str:
    """The model the analyst chose, or a clear 400 before anything is sent."""
    name = AI_PROVIDERS[mode][0]
    value = (model or "").strip()
    if not value:
        raise HTTPException(400, f"Choose a {name} model first: Settings → Providers and API keys → "
                                 f"{name} → Load models. VEILUX does not pick a model for you.")
    if not MODEL_ID_PATTERN.fullmatch(value):
        raise HTTPException(400, f"{name}: “{value[:80]}” is not a valid model ID. Choose one from Load models.")
    return value


def provider_failure(name: str, model: Optional[str], response: httpx.Response) -> HTTPException:
    """A clear error for a failed provider call. Never retries with another model."""
    detail = _extract_api_error_detail(response)
    code = response.status_code
    text = detail or ""
    if code in (401, 403) and not _MODEL_UNAVAILABLE.search(text):
        return HTTPException(code, f"{name} refused the API key (HTTP {code}). Check the key in Settings → Providers and API keys.")
    if code == 429:
        return HTTPException(429, f"{name} is rate-limiting this key right now (HTTP 429). Wait a moment and try again.")
    if code in (400, 422) and _OUTPUT_LIMIT_PARAMETER.search(text):
        return HTTPException(400, f"{name} refused the output limit for “{model}”: {text[:200]} Lower Maximum output "
                                  f"tokens in Settings → Providers and API keys → {name} → Advanced.")
    if model and (code == 404 or _MODEL_UNAVAILABLE.search(text)):
        return HTTPException(400, f"{name}: the model “{model}” is not available to this API key (it may have been "
                                  "retired or renamed). Choose another model in Settings → Providers and API keys → "
                                  f"{name} → Load models. No other model was tried.")
    return HTTPException(code if 400 <= code < 600 else 502, f"{name} returned HTTP {code}" + (f": {text[:200]}" if text else "."))


# Gemini finish reasons that mean the answer was withheld, not completed.
_GEMINI_WITHHELD = {"SAFETY", "RECITATION", "LANGUAGE", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "OTHER",
                    "MALFORMED_RESPONSE", "PUP_LIMITED_DISABLED"}


def _without_thinking(text: str) -> str:
    """Content with a leading <think>…</think> block removed, as some reasoning
    models (Groq's raw format, DeepSeek-R1 on Together) write their reasoning."""
    stripped = text.lstrip()
    if not stripped.startswith("<think>"):
        return text
    end = stripped.find("</think>")
    return "" if end < 0 else stripped[end + len("</think>"):]


def answer_parts(api_format: str, data) -> Tuple[str, str]:
    """The visible answer in a chat response, and why it ended: "limit" (the
    output limit was reached), "withheld: <reason>", "reasoning only" or "".
    Thinking (Claude thinking blocks, Gemini thought parts, reasoning fields)
    is never part of the answer."""
    if not isinstance(data, dict):
        return "", ""
    if api_format == "anthropic":
        blocks = data.get("content") if isinstance(data.get("content"), list) else []
        text = "".join(block["text"] for block in blocks if isinstance(block, dict)
                       and block.get("type", "text") == "text" and isinstance(block.get("text"), str))
        stop = data.get("stop_reason")
        return text, "limit" if stop == "max_tokens" else "withheld: refusal" if stop == "refusal" else ""
    if api_format == "gemini":
        candidates = data.get("candidates") if isinstance(data.get("candidates"), list) else []
        if not candidates:
            reason = (data.get("promptFeedback") or {}).get("blockReason") if isinstance(data.get("promptFeedback"), dict) else None
            return "", f"withheld: {reason}" if reason else ""
        candidate = candidates[0] if isinstance(candidates[0], dict) else {}
        parts = (candidate.get("content") or {}).get("parts") if isinstance(candidate.get("content"), dict) else None
        text = "".join(part["text"] for part in parts or [] if isinstance(part, dict)
                       and not part.get("thought") and isinstance(part.get("text"), str))
        reason = candidate.get("finishReason") or ""
        return text, "limit" if reason == "MAX_TOKENS" else f"withheld: {reason}" if reason in _GEMINI_WITHHELD else ""
    choices = data.get("choices") if isinstance(data.get("choices"), list) else []
    choice = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(part["text"] for part in content if isinstance(part, dict)
                          and part.get("type", "text") in ("text", "output_text") and isinstance(part.get("text"), str))
    text = _without_thinking(content) if isinstance(content, str) else ""
    finish = choice.get("finish_reason")
    if finish == "length":
        return text, "limit"
    if finish == "content_filter":
        return text, "withheld: content filter"
    if not text.strip() and (message.get("reasoning_content") or message.get("reasoning")):
        return text, "reasoning only"
    return text, ""


def usable_answer(label: str, text: str, ending: str, limit: int, setting: str) -> str:
    """The answer to show, or an HTTPException that says why there is none.
    A request is never reported as answered without visible text, and nothing
    is retried with a larger limit: that would spend more of the analyst's
    tokens without asking."""
    if ending.startswith("withheld"):
        raise HTTPException(400, f"{label} withheld the answer ({ending.split(': ', 1)[1]}). "
                                 "Rephrase the analysis prompt or choose another model.")
    if not text.strip():
        if ending == "limit":
            raise HTTPException(502, f"{label} reached its output limit ({limit:,} tokens) before writing an answer; "
                                     f"a reasoning model can spend it all on thinking. Raise {setting}, or choose a "
                                     "lower reasoning effort if the model offers one.")
        if ending == "reasoning only":
            raise HTTPException(502, f"{label} returned only its reasoning and no answer. Try again, or choose a lower "
                                     "reasoning effort if the model offers one.")
        raise HTTPException(502, f"{label} returned no answer text. Try again or choose another model.")
    if ending == "limit":
        job = _job_context.get()
        if job is not None:
            job["answer_cut_off"] = True
        text += (f"\n\n---\n*The answer was cut off at the output limit ({limit:,} tokens). "
                 f"Raise {setting} to get it complete.*")
    return text


def _advanced(name: str) -> str:
    return f"Maximum output tokens (Settings → Providers and API keys → {name} → Advanced)"


async def _openai_style_chat(mode: str, prompt: str, api_key: str, model: Optional[str], timeout: float,
                             generation: Optional[GenerationSettings] = None) -> str:
    name, endpoint = AI_PROVIDERS[mode]
    model = chosen_model(mode, model)
    limit = output_limit(generation)
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2}
    # Groq deprecated max_tokens in favour of max_completion_tokens.
    payload["max_completion_tokens" if mode == "groq" else "max_tokens"] = limit
    if mode == "deepseek" and generation:
        # DeepSeek: "thinking" switches thinking mode; reasoning_effort sets its depth.
        if generation.thinking != "default":
            payload["thinking"] = {"type": "enabled" if generation.thinking == "on" else "disabled"}
        if generation.effort and generation.thinking != "off":
            payload["reasoning_effort"] = generation.effort
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        response = await client.post(
            endpoint,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload
        )
    if response.status_code != 200:
        raise provider_failure(name, model, response)
    try:
        data = response.json()
    except ValueError:
        raise HTTPException(502, f"{name} ({model}) returned an answer VEILUX could not read.") from None
    return usable_answer(f"{name} ({model})", *answer_parts("openai", data), limit, _advanced(name))


async def call_groq_ai(prompt: str, api_key: str, model: Optional[str] = None,
                       generation: Optional[GenerationSettings] = None) -> str:
    return await _openai_style_chat("groq", prompt, api_key, model, 60.0, generation)


async def call_deepseek_ai(prompt: str, api_key: str, model: Optional[str] = None,
                           generation: Optional[GenerationSettings] = None) -> str:
    return await _openai_style_chat("deepseek", prompt, api_key, model, 120.0, generation)


async def call_together_ai(prompt: str, api_key: str, model: Optional[str] = None,
                           generation: Optional[GenerationSettings] = None) -> str:
    return await _openai_style_chat("together", prompt, api_key, model, 90.0, generation)


OPENROUTER_API = "https://openrouter.ai/api/v1"


async def call_openrouter_ai(prompt: str, api_key: str, model: str, generation: Optional[GenerationSettings] = None) -> str:
    limit = output_limit(generation)
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            f"{OPENROUTER_API}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "HTTP-Referer": "https://veilux.local"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2, "max_tokens": limit}
        )
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail=f"OpenRouter: {model} is rate-limited right now. Free models have low limits; "
                                                     "try again shortly or choose another model.")
    if response.status_code != 200:
        raise provider_failure("OpenRouter", model, response)
    try:
        data = response.json()
    except ValueError:
        raise HTTPException(502, f"OpenRouter ({model}) returned an answer VEILUX could not read.") from None
    # OpenRouter can report a provider failure inside a 200 response.
    if isinstance(data, dict) and data.get("error"):
        message = data["error"].get("message") if isinstance(data["error"], dict) else data["error"]
        raise HTTPException(status_code=502, detail=f"OpenRouter ({model}): {upstream_text(message or 'request failed', response, 200)}")
    return usable_answer(f"OpenRouter ({model})", *answer_parts("openai", data), limit, _advanced("OpenRouter"))


def _price_is_zero(value) -> bool:
    try:
        return float(value) == 0
    except (TypeError, ValueError):
        return False


def openrouter_free_models(models: list, today: Optional[str] = None) -> list:
    """Free models from OpenRouter's /models list that can analyse logs.

    Free: prompt and completion both cost 0 (negative prices mean "variable",
    as on routers). Usable: answers with text only and supports chat completions.
    Models past their expiration date are left out."""
    today = today or datetime.now(timezone.utc).date().isoformat()
    result = []
    for model in models:
        if not isinstance(model, dict) or not isinstance(model.get("id"), str):
            continue
        pricing = model.get("pricing") or {}
        architecture = model.get("architecture") or {}
        if not (_price_is_zero(pricing.get("prompt")) and _price_is_zero(pricing.get("completion"))):
            continue
        if architecture.get("output_modalities") != ["text"]:
            continue
        if "/api/v1/chat/completions" not in (model.get("endpoints") or ["/api/v1/chat/completions"]):
            continue
        expires = model.get("expiration_date")
        if isinstance(expires, str) and expires[:10] < today:
            continue
        top = model.get("top_provider") or {}
        reasoning = model.get("reasoning")
        parameters = model.get("supported_parameters") or []
        result.append({
            "id": model["id"],
            "name": str(model.get("name") or model["id"])[:120],
            "description": str(model.get("description") or "")[:600],
            "context_length": model.get("context_length") if isinstance(model.get("context_length"), int) else None,
            "max_completion_tokens": top.get("max_completion_tokens") if isinstance(top.get("max_completion_tokens"), int) else None,
            "input_modalities": [str(m) for m in architecture.get("input_modalities") or []][:8],
            "created": model.get("created") if isinstance(model.get("created"), int) else None,
            "expiration_date": expires if isinstance(expires, str) else None,
            "knowledge_cutoff": model.get("knowledge_cutoff") if isinstance(model.get("knowledge_cutoff"), str) else None,
            # "always": the model reasons before every answer, which is slower and uses more of the answer budget.
            "reasoning": ("always" if reasoning.get("mandatory") else "optional") if isinstance(reasoning, dict) else "none",
            "supports_tools": "tools" in parameters,
            "moderated": bool(top.get("is_moderated")),
        })
    return sorted(result, key=lambda m: m["name"].lower())


async def call_gemini_ai(prompt: str, api_key: str, model: Optional[str] = None,
                         generation: Optional[GenerationSettings] = None) -> str:
    model = chosen_model("gemini", model)
    limit = output_limit(generation)
    async with httpx.AsyncClient(timeout=180.0, follow_redirects=False) as client:
        response = await client.post(
            provider_endpoint("gemini", model),
            headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": limit
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
                ]
            }
        )
    if response.status_code != 200:
        raise provider_failure("Gemini", model, response)
    try:
        data = response.json()
    except ValueError:
        raise HTTPException(502, f"Gemini ({model}) returned an answer VEILUX could not read.") from None
    return usable_answer(f"Gemini ({model})", *answer_parts("gemini", data), limit, _advanced("Gemini"))


async def call_claude_ai(prompt: str, api_key: str, model: Optional[str] = None,
                         generation: Optional[GenerationSettings] = None) -> str:
    model = chosen_model("claude", model)
    limit = output_limit(generation)
    # No temperature: current Claude models reject any non-default value.
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": limit}
    if generation and generation.thinking != "default":
        payload["thinking"] = {"type": "adaptive" if generation.thinking == "on" else "disabled"}
    if generation and generation.effort:
        payload["output_config"] = {"effort": generation.effort}
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=False) as client:
        response = await client.post(
            AI_PROVIDERS["claude"][1],
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json=payload
        )
    if response.status_code != 200:
        raise provider_failure("Claude", model, response)
    try:
        data = response.json()
    except ValueError:
        raise HTTPException(502, f"Claude ({model}) returned an answer VEILUX could not read.") from None
    return usable_answer(f"Claude ({model})", *answer_parts("anthropic", data), limit, _advanced("Claude"))


# ============== SIEM / SOAR API READS ==============
# The extension sends a connection's request settings and the values it found
# on the page. Each set of values fills the request templates (${name}), and a
# dotted path picks the records out of the JSON response.
#
# Requests made with the analyst's browser login on the same website run in
# the signed-in tab instead (extension/connector_browser.js). Token, password
# and cookie sign-in, other API addresses and search jobs run here.



# Connector link regexes are written once and executed by BOTH engines: the
# extension tests them in JS (page-type detection) and this backend parses
# with Python re. The two disagree on named-group syntax — JS only accepts
# (?<name>...), Python only (?P<name>...) — so each side normalizes to its
# own dialect. The lookbehind forms (?<= and (?<! are left untouched.
_JS_NAMED_GROUP = re.compile(r'\(\?<([A-Za-z_][A-Za-z0-9_]*)>')


def _normalize_regex_for_python(pattern: str) -> str:
    return _JS_NAMED_GROUP.sub(r'(?P<\1>', pattern or "")


# The link pattern is written by the analyst, but the links it reads come from
# web pages. A pattern with nested repetition can take exponential time on a
# crafted link, so matching uses the bounded regex engine (as custom rules do):
# each match stops after LINK_MATCH_SECONDS, and patterns and links are capped.
LINK_PATTERN_MAX_LENGTH = 2000
LINK_MAX_LENGTH = 8192
MAX_LINKS = 500
LINK_MATCH_SECONDS = 0.25


class LinkPatternTimeout(ValueError):
    pass


@lru_cache(maxsize=32)
def _link_pattern(link_regex: str):
    return bounded_regex.compile(_normalize_regex_for_python(link_regex), bounded_regex.VERSION0)


def parse_siem_link(url: str, link_regex: str) -> Optional[Dict[str, str]]:
    """Apply a connector's link-parsing regex to a SIEM link/URL, returning
    its named capture groups (percent-decoded) as fetch params, or None if it
    doesn't match / the regex itself is invalid. Raises LinkPatternTimeout
    when the pattern takes too long on this link."""
    if not link_regex or len(link_regex) > LINK_PATTERN_MAX_LENGTH:
        siem_log.warning("The link pattern is empty or too long.")
        return None
    if not url or len(url) > LINK_MAX_LENGTH:
        return None
    try:
        match = _link_pattern(link_regex).search(url, timeout=LINK_MATCH_SECONDS)
    except bounded_regex.error as e:
        siem_log.warning(f"Invalid link_regex: {e}")
        return None
    except TimeoutError:
        raise LinkPatternTimeout("The link pattern took too long to read a link. Simplify the pattern: "
                                 "avoid repeating a group that itself repeats, such as (a+)+.") from None
    if not match or not match.groupdict():
        return None
    params = {k: unquote(v) for k, v in match.groupdict().items() if v is not None}
    return params or None


# Template placeholder: ${name} or ${name+N} / ${name-N} for numeric offsets
# (e.g. ${context.start_time-600000} = the context record's start time minus
# 10 minutes, used to limit a search to that record's own time range).
# Dots are allowed in names — context-document fields are exposed as
# "context.<field>" (see the context flattening in fetch_siem_logs).
_TEMPLATE_VAR = re.compile(r'\$\{([A-Za-z0-9_.]+)(?:\s*([+-])\s*(\d+))?\}')


def _render_template_var(params: Dict[str, str], name: str, op: Optional[str], num: Optional[str]) -> Optional[str]:
    """Resolve one placeholder against params; None if the param is unknown
    (the placeholder is then left as-is so the failure is visible upstream)."""
    if name not in params:
        return None
    val = params[name]
    if op:
        try:
            base = int(float(val))
            return str(base + int(num) if op == '+' else base - int(num))
        except (ValueError, TypeError):
            return str(val)
    return str(val)


def _substitute_plain(text: str, params: Dict[str, str]) -> str:
    """Replace ${name} placeholders with plain (unescaped) values — used for
    URL paths, query params, and header values."""
    def repl(m):
        rendered = _render_template_var(params, m.group(1), m.group(2), m.group(3))
        return m.group(0) if rendered is None else rendered
    return _TEMPLATE_VAR.sub(repl, text or "")


def _substitute_json_body(template: str, params: Dict[str, str]) -> dict:
    """Replace ${name} placeholders inside a JSON template with JSON-escaped
    values (so a param containing a quote/backslash can't break the
    surrounding JSON structure), then parse the result."""
    def repl(m):
        rendered = _render_template_var(params, m.group(1), m.group(2), m.group(3))
        if rendered is None:
            return m.group(0)
        return json.dumps(rendered)[1:-1]  # escaped string content, without the surrounding quotes
    try:
        return json.loads(_TEMPLATE_VAR.sub(repl, template))
    except json.JSONDecodeError:
        raise ConnectorError("The request body is not valid JSON once its values are filled in. "
                             "Check it under the connection's API request step.") from None


def _resolve_path(data, path: str):
    """Walk a dotted path (dict keys and/or list indices) into a parsed
    response body, returning None if any segment is missing."""
    if not path:
        return data
    cur = data
    for part in path.split('.'):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


async def fetch_single_log(client: httpx.AsyncClient, base_url: str, params: Dict[str, str],
                           headers: dict, cookies: dict, method: str,
                           path_template: str, body_template: Optional[str],
                           response_path: str) -> Optional[dict]:
    """Fetch a single document using a connector's API template, substituting
    the params captured from its link_regex into the path/body."""
    url = _connector_url(base_url, path_template, params)

    request_kwargs = {"headers": headers, "cookies": cookies}
    if body_template and body_template.strip():
        try:
            request_kwargs["json"] = _substitute_json_body(body_template, params)
        except ConnectorError as e:
            siem_log.warning(f"api_body_template is not valid JSON after substitution: {e}")
            return None

    response = await client.request(method or "GET", url, **request_kwargs)

    if response.status_code != 200:
        siem_log.warning(f"Failed to fetch {params}: HTTP {response.status_code}")
        return None

    try:
        data = response.json()
    except json.JSONDecodeError:
        siem_log.warning(f"Response for {params} was not valid JSON")
        return None

    resolved = _resolve_path(data, response_path)
    if isinstance(resolved, list):
        return resolved[0] if resolved else None
    if isinstance(resolved, dict):
        return resolved
    return None


def _build_siem_auth(request: "SiemFetchRequest") -> Tuple[dict, dict]:
    headers = {"Content-Type": "application/json"}
    headers.update(request.api_headers_template or {})
    cookies = {}

    if request.auth_type == "cookie" and request.auth_cookie:
        if not request.auth_cookie_name:
            raise HTTPException(status_code=400, detail="Enter the cookie name under the connection's Sign-in step.")
        cookies[request.auth_cookie_name] = request.auth_cookie
    elif request.auth_type == "basic" and request.auth_username and request.auth_password:
        creds = base64.b64encode(f"{request.auth_username}:{request.auth_password}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"
    elif request.auth_type == "header" and request.auth_header_value:
        if not request.auth_header_name:
            raise HTTPException(status_code=400, detail="Enter the header name under the connection's Sign-in step.")
        headers[request.auth_header_name] = request.auth_header_value
    elif request.auth_type == "browser_session" and request.auth_cookies:
        cookies.update({k: v for k, v in request.auth_cookies.items() if v})
        for header_name, cookie_name in (request.auth_headers_from_cookies or {}).items():
            val = request.auth_cookies.get(cookie_name)
            if val:
                headers[header_name] = val

    return headers, cookies


# Access tokens from the OAuth client credentials grant, by connection.
# In memory only: a restart asks for new ones.
_OAUTH_TOKENS: Dict[str, Tuple[str, float]] = {}
_oauth_clock = time.monotonic
# The cache is looked up by an HMAC of the app sign-in, keyed with a random
# value made at start-up and never saved. It is not a password hash: it only
# lets the cache tell sign-ins apart without keeping the client secret, and
# without the key nobody can test guesses of a secret against it.
_OAUTH_CACHE_KEY = secrets.token_bytes(32)


def _oauth_key(request: "SiemFetchRequest") -> str:
    parts = (request.oauth_token_url, request.oauth_client_id, request.oauth_client_secret, request.oauth_scope)
    message = "\n".join(str(p or "") for p in parts).encode("utf-8")
    return hmac.new(_OAUTH_CACHE_KEY, message, "sha256").hexdigest()


def _first_line(text: str) -> str:
    return (text or "").strip().splitlines()[0][:300] if (text or "").strip() else ""


async def _oauth_access_token(request: "SiemFetchRequest") -> str:
    """An access token from the token address (OAuth 2.0 client credentials,
    RFC 6749 section 4.4), reused until two minutes before it expires.

    The client secret is only ever sent to a verified HTTPS token address:
    the connection's "verify the API certificate" switch does not apply here."""
    token_url = (request.oauth_token_url or "").strip()
    if not token_url or not (request.oauth_client_id or "").strip() or not request.oauth_client_secret:
        raise HTTPException(400, "Enter the token address, client ID and client secret under the connection's Sign-in step.")
    try:
        url = httpx.URL(token_url)
    except Exception:
        raise HTTPException(400, "The token address is not a valid URL.")
    if url.userinfo or not url.host or not (url.scheme == "https" or (url.scheme == "http" and is_loopback_address(url.host))):
        raise HTTPException(400, "The token address must be an https:// address without a user name or password.")
    refused = refused_destination_reason(url.host)
    if refused:
        raise HTTPException(400, "The token address is refused: " + refused)
    key = _oauth_key(request)
    cached = _OAUTH_TOKENS.get(key)
    if cached and cached[1] > _oauth_clock():
        return cached[0]
    form = {"grant_type": "client_credentials", "client_id": request.oauth_client_id.strip(),
            "client_secret": request.oauth_client_secret}
    if (request.oauth_scope or "").strip():
        form["scope"] = request.oauth_scope.strip()
    try:
        verify = await asyncio.to_thread(_connector_ssl_context, request.tls_trust, request.ca_bundle_pem)
    except ConnectorError as exc:
        raise HTTPException(400, str(exc)) from exc
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=verify, follow_redirects=False) as client:
            response = await client.post(str(url), data=form, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        certificate_error = _siem_certificate_error(exc)
        raise HTTPException(502, "Could not reach the token address. " + (certificate_error or "Check the address and the network.")) from exc
    try:
        body = response.json()
    except ValueError:
        body = {}
    body = body if isinstance(body, dict) else {}
    token = body.get("access_token")
    if response.status_code != 200 or not isinstance(token, str) or not token:
        reason = ": ".join(t for t in (str(body.get("error") or ""), _first_line(str(body.get("error_description") or ""))) if t)
        raise HTTPException(502, f"The token address refused the app sign-in (HTTP {response.status_code})"
                            + (f" — {reason}" if reason else "")
                            + ". Check the token address (tenant), client ID, client secret and scope.")
    if str(body.get("token_type") or "Bearer").lower() != "bearer":
        raise HTTPException(502, "The token address returned a token type other than Bearer, which VEILUX cannot send.")
    try:
        lifetime = int(float(body.get("expires_in", 3600)))
    except (TypeError, ValueError):
        lifetime = 3600
    if len(_OAUTH_TOKENS) >= 64:
        _OAUTH_TOKENS.clear()
    _OAUTH_TOKENS[key] = (token, _oauth_clock() + max(30, min(lifetime, 86400) - 120))
    return token


async def _apply_oauth(request: "SiemFetchRequest", headers: dict) -> None:
    if request.auth_type == "oauth_client_credentials":
        headers["Authorization"] = "Bearer " + await _oauth_access_token(request)


def _forget_oauth_token(request: "SiemFetchRequest") -> None:
    if request.auth_type == "oauth_client_credentials":
        _OAUTH_TOKENS.pop(_oauth_key(request), None)


def _has_auth(request: "SiemFetchRequest", headers: dict, cookies: dict) -> bool:
    """True if _build_siem_auth produced any credential (session cookie,
    basic Authorization, or a token header)."""
    if request.auth_type == "none" or cookies or "Authorization" in headers:
        return True
    return request.auth_type == "header" and bool(request.auth_header_value)


def _describe_request_values(params):
    """A short, local-only label naming the values one request used, such as id=abc."""
    if not isinstance(params, dict):
        return ''
    parts = [f"{key}={str(value)[:60]}" for key, value in params.items() if key != 'query' and not key.startswith('_')]
    return ', '.join(parts[:3]) + (', …' if len(parts) > 3 else '')


def _summarize_request_errors(errors):
    if len(errors) == 1:
        return errors[0]
    return f"All {len(errors)} requests failed. First failure: {errors[0]}"


class ConnectorError(ValueError):
    """A connector failure described by VEILUX itself. Its message is written
    for the analyst; it is the only exception text a response may repeat."""


class _SiemAccessError(ConnectorError):
    """A sign-in/permission failure or redirect with an actionable message."""

    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


def _siem_signin_advice(request):
    if request.auth_type == 'cookie':
        return ('If the log opens in your browser, choose “Use my current browser login” under Sign-in; '
                'One named browser cookie can omit other required session cookies. '
                'Keep the API address pointing to the SIEM, not the case-management website.')
    if request.auth_type == 'browser_session':
        return ('Open the SIEM in the same browser and sign in again. Confirm the API address belongs to that SIEM '
                'and accepts browser sign-in. If it requires a separate API token, choose API key or access token.')
    if request.auth_type == 'header':
        return 'Check that the API token is current, uses the required header and has permission to read these records.'
    if request.auth_type == 'basic':
        return 'Check that the API accepts this username/password and that the account can read these records.'
    if request.auth_type == 'oauth_client_credentials':
        return ('A token was issued, but the API refused it. Check the scope (it must name this API) and that the app '
                'has been granted a role or permission that can read these records.')
    return 'Choose the sign-in method required by this API under the connection’s Sign-in step.'


def _siem_access_message(response, request):
    code = response.status_code
    if code == 401:
        message = 'The SIEM rejected the sign-in sent by VEILUX (HTTP 401). '
    elif code == 403:
        message = 'The SIEM denied this request (HTTP 403). Check account permissions and any required security headers. '
    elif code in (301, 302, 303, 307, 308):
        message = (f'The SIEM redirected the request (HTTP {code}). This may be a sign-in page or a different API path. '
                   'Check the API address and request path. ')
    else:
        return None
    # Do not expose a redirect URL or response body: either can contain sign-in tokens.
    return message + _siem_signin_advice(request)


def _check_siem_access(response, request):
    message = _siem_access_message(response, request)
    if message:
        raise _SiemAccessError(message, response.status_code)


@lru_cache(maxsize=16)
def _connector_ssl_context(trust, ca_pem):
    context = ssl.create_default_context(cafile=certifi.where())
    if trust == 'system':
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    if ca_pem.strip():
        if 'PRIVATE KEY' in ca_pem or '-----BEGIN CERTIFICATE-----' not in ca_pem:
            raise ConnectorError('Use a public CA certificate in PEM format, not a private key.')
        try:
            context.load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError) as exc:
            raise ConnectorError('The CA certificate could not be read. Use a PEM certificate or CA bundle from your IT team.') from exc
    return context


async def _connector_verify(request):
    if not request.verify_ssl:
        return False  # Preserve an explicitly saved preference; never retry with it automatically.
    try:
        return await asyncio.to_thread(_connector_ssl_context, request.tls_trust, request.ca_bundle_pem)
    except ConnectorError as exc:
        raise HTTPException(400, str(exc)) from exc


def _siem_certificate_error(exc):
    current = exc
    for _ in range(8):
        if isinstance(current, ssl.SSLCertVerificationError) or 'CERTIFICATE_VERIFY_FAILED' in str(current):
            return ('The SIEM certificate could not be verified by the backend. In this connection’s More options, '
                    'keep Verify the API certificate enabled and choose Computer trust store. '
                    'If your organization’s CA is not trusted on the backend computer, load its public CA certificate '
                    '(PEM) under Organization CA certificate. A missing intermediate, expired certificate or hostname '
                    'mismatch must be corrected on the SIEM server. No unverified retry was made.')
        current = getattr(current, '__cause__', None) or getattr(current, '__context__', None)
        if current is None:
            break
    return None


def _require_connector_values(templates, params):
    missing = {m.group(1) for template in templates if template
               for m in _TEMPLATE_VAR.finditer(template) if m.group(1) not in params}
    if missing:
        raise ConnectorError("Missing request values: " + ', '.join(sorted(missing)) + ". No value source supplied them for this page. Open the page that shows them, or add a value source or fixed value under Request values.")


# ---- Where connector requests may go ----
# The analyst chooses the API address, and it is usually inside their own
# network (a SIEM at 10.x, siem.corp.local, localhost). Private and loopback
# addresses are therefore allowed. What must never decide the destination is
# data VEILUX reads while working: values taken from a web page, a search ID or
# a context document returned by the API, a page token. Those values only ever
# fill path segments and query parameters, and every built address is checked
# to stay on the configured API address. Cloud instance-metadata endpoints are
# refused outright: no SIEM lives there, and they hand out cloud credentials.
class DestinationError(ConnectorError):
    """An outbound address VEILUX refuses to contact."""


_METADATA_HOSTS = {"metadata.google.internal", "metadata.goog", "metadata", "instance-data",
                   "instance-data.ec2.internal", "metadata.azure.internal"}
_METADATA_ADDRESSES = {ipaddress.ip_address("fd00:ec2::254")}
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def _host_address(host: str):
    """The IP address a host names without a DNS lookup, or None for a name.
    Also reads the legacy IPv4 spellings (2852039166, 0xa9fea9fe, 169.254.43518)
    that the system resolver accepts."""
    name = (host or "").strip().strip("[]").rstrip(".").lower()
    try:
        address = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        if not name or not re.fullmatch(r"[0-9a-fx.]+", name) or not re.search(r"[0-9]", name):
            return None
        try:
            address = ipaddress.ip_address(socket.inet_aton(name))
        except OSError:
            return None
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address


def refused_destination_reason(host: str) -> Optional[str]:
    """Why VEILUX will not contact this host, or None. Private networks and this
    computer are allowed; link-local, cloud-metadata, multicast, unspecified
    and reserved addresses are not."""
    name = (host or "").strip().strip("[]").rstrip(".").lower()
    if not name:
        return "The address has no host name."
    if name in _METADATA_HOSTS:
        return "VEILUX does not contact cloud instance-metadata addresses."
    address = _host_address(name)
    if address is None:
        return None
    if address in _METADATA_ADDRESSES or address.is_link_local:
        return "VEILUX does not contact link-local or cloud instance-metadata addresses (such as 169.254.169.254)."
    if address.is_multicast or address.is_unspecified or (address.is_reserved and not address.is_loopback):
        return "This IP address cannot be used as an API address."
    return None


def checked_destination(address: str, what: str = "The address", allow_userinfo: bool = False) -> httpx.URL:
    """Parse an analyst-configured address and refuse what VEILUX never contacts."""
    text = (address or "").strip()
    try:
        url = httpx.URL(text)
    except Exception:
        raise DestinationError(f"{what} is not a valid URL.") from None
    if url.scheme not in ("http", "https") or not url.host:
        raise DestinationError(f"{what} must be a complete http:// or https:// address.")
    if url.userinfo and not allow_userinfo:
        raise DestinationError(f"{what} must not contain a user name or password. "
                               "Enter them under the connection's Sign-in step instead.")
    reason = refused_destination_reason(url.host)
    if reason:
        raise DestinationError(f"{what} is refused: {reason}")
    return url


def connector_base(base_url: str) -> httpx.URL:
    url = checked_destination(base_url, "The API address")
    if url.query or url.fragment:
        raise DestinationError("The API address must not contain ? or #. Put query values in the request settings.")
    return url


def _same_destination(base: httpx.URL, built: str) -> str:
    """The built address, if it is on the API address: same scheme, host and
    port, under the API address's path, without dot segments."""
    target = httpx.URL(built)
    if (target.scheme, target.host, target.port) != (base.scheme, base.host, base.port) or target.userinfo:
        raise DestinationError("The request would leave the configured API address, so it was not sent.")
    base_path = base.path.rstrip("/")
    segments = target.path.split("/")
    if any(segment in (".", "..") for segment in segments) or not (target.path == base_path or target.path.startswith(base_path + "/")):
        raise DestinationError("The request path would leave the API address's path, so it was not sent.")
    return str(target)


def _path_value(value: str) -> str:
    """One value placed in a request path, encoded as a single path segment.
    A value that would step out of the path is refused, even if a server
    decodes %2F before resolving dot segments."""
    text = str(value)
    if _CONTROL_CHARACTERS.search(text):
        raise DestinationError("A request value contains control characters, so the request was not sent.")
    if any(part in (".", "..") for part in re.split(r"[/\\]", text)):
        raise DestinationError("A request value would change the request path (it contains . or ..), so the request was not sent.")
    return quote(text, safe="")


def _connector_url(base_url, template, params):
    if not template or not template.startswith('/') or template.startswith('//'):
        raise ConnectorError("Enter a request path beginning with /, relative to the API address.")
    base = connector_base(base_url)
    _require_connector_values([template], params)
    path = _TEMPLATE_VAR.sub(lambda m: _path_value(_render_template_var(params, m.group(1), m.group(2), m.group(3))), template)
    return _same_destination(base, str(base).rstrip('/') + path)


def _plain_url(base_url, template):
    """The address for a fixed path (connection check, platform probes): the
    template has no values from pages or responses, and it must stay on the
    API address like every other request."""
    template = template or '/'
    if not template.startswith('/') or template.startswith('//'):
        raise DestinationError("Enter a connection check path beginning with /, relative to the API address.")
    base = connector_base(base_url)
    return _same_destination(base, str(base).rstrip('/') + template)


def public_error(exc: BaseException) -> str:
    """What a failed request tells the extension. Only ConnectorError messages,
    which VEILUX writes itself, are repeated. Any other exception (a library's
    ValueError included) can carry addresses, values or response text, so only
    its kind is returned and the details stay in the backend's own log."""
    if isinstance(exc, ConnectorError) and str(exc):
        return _CONTROL_CHARACTERS.sub(" ", str(exc))[:500]
    if isinstance(exc, httpx.TimeoutException) or isinstance(exc, TimeoutError):
        return "The request timed out."
    if isinstance(exc, httpx.HTTPError):
        return "The API could not be reached (" + type(exc).__name__ + "). Check the address and the network."
    siem_log.debug("Request failed", exc_info=exc)
    return "The request failed (" + type(exc).__name__ + "). The backend window has the details."


def _connector_headers(headers, request, params):
    templates = request.api_headers_template or {}
    _require_connector_values(templates.values(), params)
    return {key: _substitute_plain(value, params) if templates.get(key) == value else value for key, value in headers.items()}


async def fetch_context_document(client: httpx.AsyncClient, base_url: str, params: Dict[str, str],
                                 headers: dict, cookies: dict,
                                 request: SiemFetchRequest) -> Optional[dict]:
    """Fetch the connector's optional per-link context document (for example
    the alert a search is about) — best-effort, a failure never breaks the
    main fetch."""
    if not request.context_path_template:
        return None
    portable = request.result_mode == 'records'
    url = _connector_url(base_url, request.context_path_template, params)
    if portable:
        headers = _connector_headers(headers, request, params)
    try:
        response = await client.request(request.context_method or "GET", url,
                                        headers=headers, cookies=cookies)
        if response.status_code != 200:
            siem_log.warning(f"Context fetch failed: HTTP {response.status_code}")
            return None
        resolved = _resolve_path(response.json(), request.context_response_path or "")
        return resolved if isinstance(resolved, (dict, list)) else None
    except Exception as e:
        siem_log.warning(f"Context fetch error: {type(e).__name__}")
        return None


async def fetch_via_search_job(client: httpx.AsyncClient, base_url: str, params: Dict[str, str],
                               headers: dict, cookies: dict,
                               request: SiemFetchRequest) -> List:
    """Run one async search-job cycle (create -> poll -> results) for a single
    parsed link. Raises on hard failures so the caller can count them.

    Example:
      create : POST /api/searches?query=...      -> {"id": ...}, kept as ${job_id}
      poll   : GET  /api/searches/${job_id}      until the status field is complete
      results: GET  /api/searches/${job_id}/results -> the records
    """
    if not request.job_create_path_template or not request.job_status_path_template \
            or not request.job_results_path_template:
        raise ConnectorError("search_job mode requires job create/status/results path templates")


    # 1. Create the job
    portable = request.result_mode == 'records'
    if portable:
        _require_connector_values([request.job_create_body_template, *(request.job_create_query_template or {}).values()], params)
        # job_id is supplied by the create response; all other values must already exist.
        _require_connector_values([request.job_status_path_template, request.job_results_path_template], {**params, 'job_id': ''})
        headers = _connector_headers(headers, request, params)
    create_url = _connector_url(base_url, request.job_create_path_template, params)
    create_kwargs = {"headers": headers, "cookies": cookies}
    as_form = request.job_create_parameters_as == "form"
    has_body = bool(request.job_create_body_template and request.job_create_body_template.strip())
    if as_form and has_body:
        raise ConnectorError("Send the search's start parameters either as a form body or with a JSON body, not both.")
    if request.job_create_query_template:
        rendered = {k: _substitute_plain(v, params) for k, v in request.job_create_query_template.items()}
        if as_form:
            create_kwargs["data"] = rendered
            # httpx sets the form content type; the default JSON one must not override it.
            create_kwargs["headers"] = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        else:
            create_kwargs["params"] = httpx.URL(create_url).params.merge(rendered) if portable else rendered
    if has_body:
        create_kwargs["json"] = _substitute_json_body(request.job_create_body_template, params)

    response = await client.request(request.job_create_method, create_url, **create_kwargs)
    _check_siem_access(response, request)
    if response.status_code not in (200, 201):
        raise ConnectorError(_http_failure("Starting the search failed", response))

    job_id = _resolve_path(response.json(), request.job_id_path)
    shown_id = upstream_text(job_id, response, 100)
    if job_id is None:
        raise ConnectorError(f"could not find job id at '{request.job_id_path}' in create response")

    job_params = dict(params)
    job_params["job_id"] = str(job_id)

    # 2. Poll until complete / error / timeout
    status_url = _connector_url(base_url, request.job_status_path_template, job_params)
    complete_values = {str(v).upper() for v in request.job_complete_values}
    error_values = {str(v).upper() for v in (request.job_error_values or [])}
    deadline = asyncio.get_event_loop().time() + max(request.job_timeout_seconds, 1.0)

    while True:
        response = await client.get(status_url, headers=headers, cookies=cookies)
        _check_siem_access(response, request)
        if response.status_code != 200:
            raise ConnectorError(_http_failure("Checking the search status failed", response))
        status_body = response.json()
        reported = _resolve_path(status_body, request.job_status_field) or ""
        status = str(reported).upper()
        if status in complete_values:
            break
        if status in error_values:
            reason = _message_text(_resolve_path(status_body, request.job_error_message_path)) if request.job_error_message_path else ""
            raise ConnectorError(f"search job {shown_id} ended in status {status}"
                                 + (f": {upstream_text(reason, response, 300)}" if reason else ""))
        if asyncio.get_event_loop().time() >= deadline:
            raise ConnectorError(f"search job {shown_id} timed out after {request.job_timeout_seconds:.0f}s "
                                 f"(last status: {upstream_text(reported, response, 60)})")
        await asyncio.sleep(max(request.job_poll_interval_seconds, 0.5))

    # 3. Fetch results, page by page when offset pagination is set
    results_url = _connector_url(base_url, request.job_results_path_template, job_params)
    paged = request.pagination_mode == 'offset' and bool(request.pagination_parameter.strip())
    records: List = []
    for page in range(request.max_pages if paged else 1):
        kwargs = {"headers": headers, "cookies": cookies}
        if paged:
            page_query = {request.pagination_parameter: str(page * request.page_size)}
            if request.pagination_size_parameter:
                page_query[request.pagination_size_parameter] = str(request.page_size)
            kwargs["params"] = httpx.URL(results_url).params.merge(page_query)
        response = await client.get(results_url, **kwargs)
        _check_siem_access(response, request)
        if response.status_code != 200:
            raise ConnectorError(_http_failure("Reading the search results failed", response))
        if request.result_mode == 'records':
            batch = _connector_records(response.json(), request)
        else:
            resolved = _resolve_path(response.json(), request.response_path or "")
            batch = [] if resolved is None else resolved if isinstance(resolved, list) else [resolved]
        records.extend(batch)
        if not paged or len(batch) < request.page_size:
            return records, False
        if len(records) >= request.max_results_per_link:
            return records, True
    # Every page was full: more results remain than the page limit allows.
    return records, True


def _connector_records(data, request):
    resolved = _resolve_path(data, request.response_path or "")
    if resolved is None:
        raise ConnectorError("No records at the configured Records location. Check it using a sample response.")
    records = resolved if isinstance(resolved, list) else [resolved]
    if request.record_format == "columns":
        columns = _resolve_path(data, request.columns_path)
        if not isinstance(columns, list):
            raise ConnectorError("Column names location must point to an array.")
        names = [c.get("name") if isinstance(c, dict) else c for c in columns]
        if not all(isinstance(n, str) and n for n in names) or len(set(names)) != len(names):
            raise ConnectorError("Column names must be unique, non-empty text.")
        if any(not isinstance(row, list) or len(row) != len(names) for row in records):
            raise ConnectorError("Each record must have one value per column name.")
        return [dict(zip(names, row)) for row in records]
    if any(not isinstance(row, dict) for row in records):
        raise ConnectorError("Records must be JSON objects. Choose column names + rows for table-shaped responses.")
    return records


def _partial_result_warning(data) -> str:
    """Some APIs answer HTTP 200 with records *and* an error object when the
    results are incomplete (Azure Monitor Logs' "PartialError")."""
    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        text = _message_text(data["error"])
        return "The API reported that the results may be incomplete" + (f": {text[:300]}" if text else ".")
    return ""


async def fetch_record_pages(client, request, params, headers, warnings=None):
    """Bounded JSON collection requests; pagination tokens never choose an origin."""
    if not request.api_path_template or not request.api_path_template.startswith('/') or request.api_path_template.startswith('//'):
        raise ConnectorError("Enter a request path beginning with /, relative to the API address.")
    if request.pagination_mode != 'none' and not request.pagination_parameter.strip():
        raise ConnectorError("Enter the pagination parameter name.")
    _require_connector_values([request.api_path_template, request.api_body_template or '', *(request.api_query_template or {}).values()], params)
    url = _connector_url(request.siem_base_url, request.api_path_template, params)
    if '${' in url:
        raise ConnectorError("The request path needs a missing link or query value. Check its placeholders.")
    query = {key: _substitute_plain(value, params) for key, value in (request.api_query_template or {}).items()}
    rendered_headers = _connector_headers(headers, request, params)
    records, cursor, seen, available = [], None, set(), None
    exhausted = False
    async with asyncio.timeout(request.connector_timeout_seconds):
        for page in range(request.max_pages):
            page_query = dict(query)
            if request.pagination_mode != 'none':
                if request.pagination_size_parameter:
                    page_query[request.pagination_size_parameter] = str(request.page_size)
                if request.pagination_mode == 'offset':
                    page_query[request.pagination_parameter] = str(page * request.page_size)
                elif cursor is not None:
                    page_query[request.pagination_parameter] = str(cursor)
            kwargs = {'headers': rendered_headers, 'params': httpx.URL(url).params.merge(page_query)}
            if request.api_body_template:
                if request.api_method.upper() == 'GET':
                    raise ConnectorError("GET requests use query parameters; leave Request body empty.")
                kwargs['json'] = _substitute_json_body(request.api_body_template, params)
            response = await client.request(request.api_method, url, **kwargs)
            _check_siem_access(response, request)
            if not response.is_success:
                detail = _extract_api_error_detail(response)
                raise ConnectorError(f"API returned HTTP {response.status_code}" + (f" — {detail}" if detail else "")
                                 + ". Check the address, sign-in and request settings.")
            try:
                data = response.json()
            except ValueError:
                raise ConnectorError("The API did not return JSON. Check the request path and sign-in.")
            batch = _connector_records(data, request)
            warning = _partial_result_warning(data)
            if warning and warnings is not None and warning not in warnings:
                warnings.append(warning)
            total = _resolve_path(data, request.total_path) if request.total_path else None
            if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
                available = total
            room = request.max_results_per_link - len(records)
            records.extend(batch[:room])
            cursor = _resolve_path(data, request.pagination_cursor_path) if request.pagination_cursor_path else None
            exhausted = (not batch or (available is not None and len(records) >= available)
                or (request.pagination_mode == 'offset' and len(batch) < request.page_size)
                or (request.pagination_mode == 'cursor' and cursor in (None, '')))
            if request.pagination_mode == 'none' or exhausted or len(records) >= request.max_results_per_link:
                return records, available, len(batch) > room or (not exhausted and request.pagination_mode != 'none') or (available is not None and available > len(records))
            if request.pagination_mode == 'cursor':
                if not isinstance(cursor, (str, int)) or str(cursor) in seen:
                    raise ConnectorError("The API returned a repeated or invalid page token. Check pagination settings.")
                seen.add(str(cursor))
    return records, available, not exhausted


async def _fetch_siem_logs(request: SiemFetchRequest):
    """
    Fetch logs from a SIEM for the record links or values read from a page,
    driven by the connector's link_regex + API template (single_request mode)
    or its search-job templates (search_job mode).
    """
    if not request.siem_links and not request.parsed_params:
        raise HTTPException(status_code=400, detail="No SIEM links or parsed params provided")
    try:
        connector_base(request.siem_base_url)
    except DestinationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    # (?!) never matches: without a link pattern, links supply no values.
    link_regex = request.link_regex or r'(?!)'
    api_path_template = request.api_path_template or ''
    api_body_template = request.api_body_template or ''
    response_path = request.response_path or ''
    if request.fetch_mode != "search_job" and not api_path_template:
        raise HTTPException(status_code=400, detail="Enter the API request path under the connection's API request step.")
    if request.fetch_mode == "search_job":
        missing = [label for label, value in (("start path", request.job_create_path_template), ("start method", request.job_create_method),
                   ("search ID location", request.job_id_path), ("status path", request.job_status_path_template),
                   ("status location", request.job_status_field), ("finished status values", request.job_complete_values),
                   ("results path", request.job_results_path_template)) if not value]
        if missing:
            raise HTTPException(status_code=400, detail="Enter the search job's " + ", ".join(missing) + " in the connection's API request step.")

    if len(request.siem_links) > MAX_LINKS:
        raise HTTPException(status_code=400, detail=f"Too many links in one request (at most {MAX_LINKS}).")
    parsed_links = []
    for link in request.siem_links:
        try:
            parsed = parse_siem_link(link, link_regex)
        except LinkPatternTimeout as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        if parsed:
            parsed_links.append(parsed)
        else:
            siem_log.warning(f"Could not parse link: {link[:100]}")

    if request.siem_links and not parsed_links and not request.parsed_params:
        raise HTTPException(status_code=400, detail="No valid SIEM links could be parsed. Check the connector's link-parsing regex in Settings.")

    for p in (request.parsed_params or []):
        if isinstance(p, dict):
            parsed_links.append({str(k): str(v) for k, v in p.items()})

    if not parsed_links:
        raise HTTPException(status_code=400, detail="Nothing to fetch: no links parsed and no params provided.")

    # A search job for the same params (e.g. the same record linked twice on
    # one page) is expensive — dedupe parsed links.
    unique_links = []
    seen_params = set()
    for params in parsed_links:
        key = tuple(sorted(params.items()))
        if key not in seen_params:
            seen_params.add(key)
            unique_links.append(params)

    headers, cookies = _build_siem_auth(request)
    await _apply_oauth(request, headers)
    if not _has_auth(request, headers, cookies):
        raise HTTPException(status_code=400, detail="No valid auth provided. Configure the connector's auth (cookie/basic/header token) in Settings.")

    fetched_logs = []
    record_logs = []
    failed_count = 0
    collection_totals, collection_limited, errors, warnings = [], False, [], []
    # Search jobs poll for up to job_timeout_seconds each — the client
    # timeout only bounds individual requests, not the whole job.
    request_timeout = 30.0 if request.fetch_mode != "search_job" else max(30.0, request.job_poll_interval_seconds + 15.0)

    async with httpx.AsyncClient(timeout=request_timeout, verify=await _connector_verify(request), follow_redirects=False) as client:
        if request.result_mode == 'records':
            client.cookies.update(cookies)
        for params in unique_links:
            request_label = 'configured request' if request.result_mode == 'records' else str(params)
            remaining = request.max_results_per_link - len(record_logs) if request.result_mode == 'records' else request.max_results_per_link
            if remaining <= 0:
                collection_limited = True
                break
            record_request = request.model_copy(update={'max_results_per_link': remaining})
            context_doc = None
            try:
                # Optional context document first, so it leads the extracted logs.
                context_doc = await fetch_context_document(
                    client, request.siem_base_url, params, headers, cookies, request
                )
                if context_doc is not None:
                    fetched_logs.append(json.dumps(context_doc, indent=2, ensure_ascii=False))

                # Chain the context document into later templates: its
                # top-level scalar fields become ${context.<field>} params,
                # so e.g. a search can be limited to the record's own time
                # range (${context.start_time-600000} ...) instead of
                # scanning days of data.
                if isinstance(context_doc, dict):
                    params = dict(params)
                    for k, v in context_doc.items():
                        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                            params["context." + str(k)] = str(v)

                if request.fetch_mode == "search_job":
                    async with asyncio.timeout(request.job_timeout_seconds):
                        results, more = await fetch_via_search_job(client, request.siem_base_url, params, headers, cookies, request)
                    collection_limited = collection_limited or more or len(results) > remaining
                    capped = results[:remaining]
                    for item in capped:
                        serialized = json.dumps(item, indent=2, ensure_ascii=False)
                        fetched_logs.append(serialized)
                        record_logs.append(serialized)
                    if capped:
                        siem_log.info(f"Search job for {request_label}: {len(capped)} event(s)"
                              + (f" (capped from {len(results)})" if len(results) > len(capped) else ""))
                    elif context_doc is None:
                        failed_count += 1
                        siem_log.warning(f"Search job for {request_label} returned no events")
                elif request.result_mode == 'records':
                    records, available, limited = await fetch_record_pages(client, record_request, params, headers, warnings)
                    serialized = [json.dumps(item, indent=2, ensure_ascii=False) for item in records]
                    fetched_logs.extend(serialized)
                    record_logs.extend(serialized)
                    collection_totals.append(available)
                    collection_limited = collection_limited or limited
                else:
                    hit = await fetch_single_log(
                        client, request.siem_base_url, params,
                        headers, cookies, request.api_method,
                        api_path_template, api_body_template, response_path
                    )
                    if hit:
                        fetched_logs.append(json.dumps(hit, indent=2, ensure_ascii=False))
                        record_logs.append(fetched_logs[-1])
                        siem_log.info(f"Fetched {request_label}")
                    elif context_doc is None:
                        failed_count += 1
                        siem_log.warning(f"Empty result for {request_label}")
            except Exception as e:
                # A failure for one record (403, 404, …) skips only that record.
                # A rejected sign-in or a redirect stops all further requests.
                if isinstance(e, _SiemAccessError) and e.status_code != 403:
                    if e.status_code == 401:
                        _forget_oauth_token(request)
                    raise HTTPException(502, str(e)) from e
                certificate_error = _siem_certificate_error(e)
                if certificate_error:
                    raise HTTPException(502, certificate_error) from e
                label = _describe_request_values(params)
                errors.append((f"For {label}: " if label else "") + public_error(e))
                if request.result_mode == 'records' and context_doc is not None:
                    failed_count += 1
                if context_doc is not None:
                    # The context document still made it —
                    # report a partial failure rather than discarding the link.
                    siem_log.warning(f"Events fetch failed for {request_label} (context kept): {type(e).__name__}")
                else:
                    failed_count += 1
                    siem_log.warning(f"Error fetching {request_label}: {type(e).__name__}")

    if not fetched_logs and (errors or request.result_mode != 'records'):
        raise HTTPException(
            status_code=502,
            detail=(_summarize_request_errors(errors) if request.result_mode == 'records' and errors else f"Could not fetch any logs from SIEM. "
                   f"All {len(unique_links)} requests failed. "
                   f"Check your SIEM session/token — you may need to re-authenticate.")
        )

    return {
        "logs": fetched_logs,
        "record_logs": record_logs,
        "fetched": len(fetched_logs),
        "failed": failed_count,
        "available_total": sum(collection_totals) if collection_totals and len(collection_totals) == len(unique_links) and all(v is not None for v in collection_totals) else None,
        "limited": collection_limited,
        "errors": errors,
        "warnings": warnings,
        "total_links": len(request.siem_links),
        "parsed_links": len(unique_links)
    }


@app.post("/fetch-siem-logs")
async def fetch_siem_logs(request: SiemFetchRequest):
    try:
        async with asyncio.timeout(request.connector_timeout_seconds if request.result_mode == 'records' else None):
            return await _fetch_siem_logs(request)
    except TimeoutError:
        raise HTTPException(504, "Extraction took too long and was stopped. Narrow the query or lower the page limit.")


def _message_text(value, depth: int = 0) -> str:
    """The readable part of an API's error or message object.

    Handles the common shapes: a plain string; {"message": ...} or {"reason": ...}
    with nested details (Azure's "innererror" chain and "details" list,
    Elasticsearch's "caused_by"); and lists of messages such as Splunk's
    [{"type": "FATAL", "text": ...}], where errors win over informational ones."""
    if depth > 6 or value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        serious = [v for v in value if isinstance(v, dict) and str(v.get("type", "")).upper() in ("FATAL", "ERROR")]
        texts = [t for t in (_message_text(v, depth + 1) for v in (serious or value)[:3]) if t]
        return "; ".join(dict.fromkeys(texts))
    if isinstance(value, dict):
        text = next((value[key].strip() for key in ("message", "text", "reason", "description", "error_description", "detail")
                     if isinstance(value.get(key), str) and value[key].strip()), "")
        for key in ("innererror", "innerError", "caused_by", "details"):
            inner = _message_text(value.get(key), depth + 1)
            if inner and inner not in text:
                text = f"{text}: {inner}" if text else inner
        return text
    return ""


def _extract_api_error_detail(response: httpx.Response) -> str:
    """The human-readable reason in an API's JSON error, or "". Most APIs name
    the field differently, so the common names are tried. A body without one
    (an HTML page, a stack trace, an echo of the request) is never repeated."""
    try:
        body = response.json()
    except ValueError:
        return ""
    text = ""
    if isinstance(body, dict):
        for key in ("description", "message", "error", "detail", "reason", "messages", "error_messages"):
            text = _message_text(body.get(key))
            if text:
                break
        http_resp = body.get("http_response")
        if not text and isinstance(http_resp, dict) and isinstance(http_resp.get("message"), str):
            text = http_resp["message"]
    return upstream_text(text, response, 300)


def upstream_text(text, response: httpx.Response, limit: int) -> str:
    """Text from a service's reply as a message may repeat it: any credential
    the request sent is hidden, control characters are removed and the length
    is bounded."""
    return _CONTROL_CHARACTERS.sub(" ", _hide_sent_credentials(str(text), response))[:limit]


def _hide_sent_credentials(text: str, response: httpx.Response) -> str:
    """An error message with any credential the request sent (a header value,
    or the password of basic sign-in) replaced, in case the server echoed it.
    Values of six characters or more are replaced wherever they appear."""
    try:
        sent = response.request.headers
    except RuntimeError:  # a response built without a request
        return text
    values = []
    for name, value in sent.items():
        if name.lower() in ("content-type", "accept", "content-length", "host", "user-agent", "accept-encoding", "connection"):
            continue
        values.append(value)
        if name.lower() == "cookie":
            values.extend(part.split("=", 1)[-1].strip() for part in value.split(";"))
        scheme, _, credential = value.partition(" ")
        if credential:
            values.append(credential)
            if scheme.lower() == "basic":
                try:
                    values.extend(base64.b64decode(credential).decode("utf-8", "replace").split(":", 1))
                except ValueError:
                    pass
    for value in sorted({v for v in values if v}, key=len, reverse=True):
        if len(value) >= 6:
            text = text.replace(value, "[hidden]")
        else:
            # A short value is hidden where it stands alone, so that a value such
            # as "en" does not blank out every word containing those letters.
            text = re.sub(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])", "[hidden]", text)
    return text


def _http_failure(what: str, response: httpx.Response) -> str:
    detail = _extract_api_error_detail(response)
    return f"{what}: HTTP {response.status_code}" + (f" — {detail}" if detail else "")


# When a connection check fails on the configured path, these well-known
# health endpoints identify the platform, so the message can suggest the
# matching template instead of a bare 404.
PLATFORM_PROBES = [
    ("qradar", "IBM QRadar", "/api/help/versions", '"version"'),
    ("opensearch", "OpenSearch Dashboards", "/api/status", '"status"'),
    ("elasticsearch", "Elasticsearch / OpenSearch node", "/", '"cluster_name"'),
    ("splunk", "Splunk", "/services/server/info?output_mode=json", "splunk"),
]
# QRadar's 404 wording is unique, so it identifies QRadar even when the
# health endpoints above are not permitted.
QRADAR_404_SIGNATURE = "is not a known endpoint resource"


async def _detect_platform(client: httpx.AsyncClient, base_url: str,
                           headers: dict, cookies: dict) -> Optional[Dict]:
    for key, label, path, marker in PLATFORM_PROBES:
        try:
            resp = await client.get(_plain_url(base_url, path),
                                    headers=headers, cookies=cookies, timeout=6.0)
            if resp.status_code == 200 and marker in resp.text.lower():
                return {"platform": key, "label": label, "health_path": path, "authenticated": True}
        except Exception:
            continue
    return None


@app.post("/test-siem")
async def test_siem_connection(request: SiemFetchRequest):
    """Test SIEM connectivity — tries to reach the SIEM's health-check path with the provided auth.
    On a wrong-path failure, probes known platform fingerprints so the UI can
    suggest the right preset ('this looks like IBM QRadar')."""
    try:
        connector_base(request.siem_base_url)
    except DestinationError as exc:
        return {"status": "error", "message": str(exc)}
    headers, cookies = _build_siem_auth(request)
    await _apply_oauth(request, headers)
    test_path = request.test_path or '/'

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=await _connector_verify(request), follow_redirects=False) as client:
            url = _plain_url(request.siem_base_url, test_path)
            response = await client.get(url, headers=headers, cookies=cookies)
            if response.status_code == 200:
                return {"status": "connected", "http_code": 200,
                        "message": "Connection check succeeded; record access has not been checked. Use Preview extraction to verify records."}
            detail = _extract_api_error_detail(response)
            if response.status_code == 401:
                _forget_oauth_token(request)
            if response.status_code in (401, 403):
                message = (f"SIEM refused the credentials (HTTP {response.status_code})"
                           + (f": {detail}" if detail else "")
                           + " — " + _siem_signin_advice(request))
                return {"status": "auth_failed", "http_code": response.status_code, "message": message}

            redirect_message = _siem_access_message(response, request)
            if redirect_message:
                return {"status": "redirected", "http_code": response.status_code, "message": redirect_message}

            # Not a sign-in problem, so the check path is probably wrong for
            # this platform. Try to identify the platform.
            detection = await _detect_platform(client, request.siem_base_url, headers, cookies)
            if detection is None and QRADAR_404_SIGNATURE in (response.text or ""):
                detection = {"platform": "qradar", "label": "IBM QRadar",
                             "health_path": "/api/help/versions", "authenticated": False}
            if detection:
                auth_note = "reachable and authenticated" if detection.get("authenticated") else "reachable"
                return {
                    "status": "reachable",
                    "http_code": response.status_code,
                    "detected_platform": detection["platform"],
                    "detected_label": detection["label"],
                    "detected_health_path": detection["health_path"],
                    "message": (f"SIEM {auth_note} — it looks like {detection['label']}, but this "
                                f"connector's health path ({test_path}) doesn't exist on that platform. "
                                f"Pick the {detection['label']} preset in step 1 to configure everything automatically.")
                }

            message = (f"SIEM returned HTTP {response.status_code}"
                       + (f": {detail}" if detail else ""))
            return {"status": "error", "http_code": response.status_code, "message": message}
    except httpx.ConnectError as exc:
        certificate_error = _siem_certificate_error(exc)
        return {"status": "certificate_error" if certificate_error else "unreachable",
                "message": certificate_error or "Cannot reach SIEM server. Check URL and network."}
    except HTTPException:
        raise
    except Exception as e:
        siem_log.warning(f"Connection check failed: {type(e).__name__}")
        return {"status": "error", "message": public_error(e)}


@app.post("/feedback")
async def submit_feedback(feedback: FeedbackRequest):
    # A correction is saved as a pending lesson. Once approved in Settings it
    # is quoted into future prompts (see build_prompt), including calls to
    # external AI providers on other cases. Pattern-sanitize everything before
    # it is written, whatever the sanitize switch was on the original analysis.
    to_sanitize = [
        feedback.original_log,
        feedback.analyst_data or "",
        feedback.ai_response,
        feedback.user_correction
    ]
    # Secret placeholders are persisted without their restoration map, so a
    # later prompt can never recover or transmit the original credential.
    protected, _, _ = await local_work(
        protect_secret_inputs,
        to_sanitize,
        feedback.allowed_ambiguous_secrets,
        feedback.force_hide_values,
        feedback.secret_protection.model_dump(),
        None,
        feedback.custom_regex_rules,
        feedback.heuristic_field_exclusions,
        feedback.heuristic_settings,
    )
    sanitized, _ = await local_work(sanitize_logs, protected, enable_pattern=True,
                                    custom_regex_rules=feedback.custom_regex_rules)

    entry = {
        "id": uuid.uuid4().hex,
        "status": "pending",
        "timestamp": datetime.now().isoformat(),
        "original_log": sanitized[0][:500],
        "analyst_data": sanitized[1][:500],
        "ai_response": sanitized[2][:200],
        "user_correction": sanitized[3]
    }
    entries = training_data["feedback_entries"]
    entries.append(entry)
    # Over the limit, the oldest pending lessons go first; approved ones stay.
    while len(entries) > MAX_STORED_LESSONS:
        oldest_pending = next((i for i, e in enumerate(entries) if e.get("status") != "approved"), 0)
        entries.pop(oldest_pending)
    _save_training_data()
    return {"status": "success", "lesson": _public_lesson(entry)}


class LessonUpdate(SecretOptions):
    status: Optional[Literal["pending", "approved"]] = None
    lesson: Optional[str] = Field(default=None, max_length=2000)


def _public_lesson(entry):
    # Only the lesson text is shown; the stored log excerpt and AI answer stay local.
    return {"id": entry["id"], "status": entry.get("status", "pending"), "created": entry.get("timestamp"),
            "lesson": str(entry.get("lesson") or entry.get("user_correction") or "")}


def _find_lesson(lesson_id):
    entry = next((e for e in training_data["feedback_entries"] if e.get("id") == lesson_id), None)
    if entry is None:
        raise HTTPException(404, "Lesson not found. Reload the list; it may have been deleted.")
    return entry


@app.get("/lessons")
async def list_lessons():
    return {"lessons": [_public_lesson(e) for e in training_data["feedback_entries"]], "prompt_limit": MAX_PROMPT_LESSONS}


@app.patch("/lessons/{lesson_id}")
async def update_lesson(lesson_id: str, update: LessonUpdate):
    entry = _find_lesson(lesson_id)
    if update.lesson is not None:
        text = update.lesson.strip()
        if not text:
            raise HTTPException(400, "A lesson cannot be empty. Delete it instead.")
        # Edited text is protected the same way as a new correction.
        protected, _, _ = await local_work(protect_secret_inputs, [text], update.allowed_ambiguous_secrets,
            update.force_hide_values, update.secret_protection.model_dump(), None, update.custom_regex_rules,
            update.heuristic_field_exclusions, update.heuristic_settings)
        sanitized, _ = await local_work(sanitize_logs, protected, enable_pattern=True, custom_regex_rules=update.custom_regex_rules)
        entry["lesson"] = sanitized[0]
    if update.status is not None:
        entry["status"] = update.status
    _save_training_data()
    return _public_lesson(entry)


@app.delete("/lessons/{lesson_id}")
async def delete_lesson(lesson_id: str):
    entry = _find_lesson(lesson_id)
    training_data["feedback_entries"].remove(entry)
    _save_training_data()
    return {"deleted": lesson_id}


@app.get("/providers/openrouter/free-models")
async def openrouter_free_models_endpoint():
    """Looks up OpenRouter's current model list (public, no key needed) and
    returns the free models that can analyse logs. Nothing is cached, so each
    lookup shows what is free right now."""
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(f"{OPENROUTER_API}/models")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach OpenRouter: {type(exc).__name__}. Check this computer's internet access.")
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"OpenRouter's model list answered HTTP {response.status_code}. Try again later.")
    try:
        models = response.json().get("data")
    except ValueError:
        models = None
    if not isinstance(models, list):
        raise HTTPException(status_code=502, detail="OpenRouter's model list had an unexpected format.")
    free = openrouter_free_models(models)
    return {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "total_models": len(models), "count": len(free), "models": free}


# ---- Model lists ----
# "Load models" in Settings asks the provider which models this key can use.
# Only the API key is sent: never logs, notes, prompts or case data. Nothing is
# cached and no model is chosen here; the analyst picks one.
PROVIDER_MODEL_LISTS = {
    "groq": "https://api.groq.com/openai/v1/models",
    "deepseek": "https://api.deepseek.com/models",
    "together": "https://api.together.xyz/v1/models",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
    "claude": "https://api.anthropic.com/v1/models",
}
# Listed by the providers, but they cannot answer a chat request.
_NOT_CHAT_MODEL = re.compile(r"whisper|tts|embed|guard|moderation|transcri|speech|playai|orpheus|rerank|image",
                             re.IGNORECASE)
MODEL_LIST_MAX_PAGES = 5


class ProviderModelsRequest(BaseModel):
    api_key: Optional[str] = Field(default=None, max_length=1000)
    custom_provider: Optional[CustomProviderConfig] = None  # for provider "custom"


def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


# Claude lists effort levels as an object; show them from least to most.
_EFFORT_ORDER = ["none", "minimal", "low", "medium", "high", "xhigh", "max"]


def _reasoning_options(style: str, m: dict) -> Dict:
    """The reasoning settings a model reports in its provider's model list:
    DeepSeek's effort.supported_levels, Claude's capabilities.effort and
    capabilities.thinking.types. Nothing is assumed for models that report
    none, so the analyst is never offered a setting the model would refuse."""
    if style == "deepseek":
        effort = m.get("effort") if isinstance(m.get("effort"), dict) else {}
        levels = [str(level) for level in effort.get("supported_levels") or [] if isinstance(level, str)]
        default = effort.get("default_level")
        # Only models with effort levels think, so only they get the switch.
        return {"efforts": levels[:8], "default_effort": default if default in levels else None, "thinking_switch": bool(levels)}
    if style == "claude":
        capabilities = m.get("capabilities") if isinstance(m.get("capabilities"), dict) else {}
        effort = capabilities.get("effort") if isinstance(capabilities.get("effort"), dict) else {}
        levels = [key for key, value in effort.items() if isinstance(value, dict) and value.get("supported") is True]
        levels.sort(key=lambda level: _EFFORT_ORDER.index(level) if level in _EFFORT_ORDER else len(_EFFORT_ORDER))
        thinking = capabilities.get("thinking") if isinstance(capabilities.get("thinking"), dict) else {}
        types = thinking.get("types") if isinstance(thinking.get("types"), dict) else {}
        supported = lambda kind: isinstance(types.get(kind), dict) and types[kind].get("supported") is True
        return {"efforts": levels[:8], "default_effort": None, "thinking_switch": supported("adaptive") and supported("disabled")}
    return {"efforts": [], "default_effort": None, "thinking_switch": False}


def _model_entry(model_id, name=None, context=None, created=None, owner=None, max_output=None, reasoning=None):
    return {"id": model_id, "name": str(name or model_id)[:120],
            "context_length": _count(context),
            "created": created if isinstance(created, (int, str)) and not isinstance(created, bool) else None,
            "owned_by": str(owner)[:80] if owner else None,
            # The largest answer the provider allows, thinking included; the
            # extension keeps Maximum output tokens at or below it.
            "max_output_tokens": _count(max_output),
            **(reasoning or {"efforts": [], "default_effort": None, "thinking_switch": False})}


def parse_model_list(style: str, body) -> List[Dict]:
    """The chat-capable models in one page of a provider's model list."""
    found = []
    if style == "gemini":
        for m in (body.get("models") if isinstance(body, dict) else None) or []:
            if not isinstance(m, dict) or not isinstance(m.get("name"), str):
                continue
            if "generateContent" not in (m.get("supportedGenerationMethods") or []):
                continue
            model_id = m["name"].removeprefix("models/")
            found.append(_model_entry(model_id, m.get("displayName"), m.get("inputTokenLimit"),
                                      max_output=m.get("outputTokenLimit")))
        return found
    items = body if isinstance(body, list) else (body.get("data") if isinstance(body, dict) else None)
    for m in items or []:
        if not isinstance(m, dict) or not isinstance(m.get("id"), str) or not m["id"].strip():
            continue
        if m.get("active") is False:
            continue
        kind = m.get("type")
        if style == "together" and kind is not None and kind != "chat":
            continue
        if _NOT_CHAT_MODEL.search(m["id"]):
            continue
        found.append(_model_entry(m["id"], m.get("display_name") or m.get("name"),
                                  m.get("context_window") or m.get("context_length") or m.get("max_input_tokens"),
                                  m.get("created") or m.get("created_at"), m.get("owned_by") or m.get("organization"),
                                  # DeepSeek: max_output_tokens; Groq: max_completion_tokens; Claude: max_tokens.
                                  m.get("max_output_tokens") or m.get("max_completion_tokens") or m.get("max_tokens"),
                                  _reasoning_options(style, m)))
    return found


def custom_models_url(config: CustomProviderConfig) -> str:
    """Where a custom service lists its models, worked out from its chat URL;
    DestinationError when it cannot be (the analyst then types the model ID)."""
    url = checked_destination(config.endpoint.replace("{model}", "x"), f"{config.name or 'Custom model'}: the service URL",
                              allow_userinfo=True)
    path = url.path
    if config.api_format == "openai" and path.endswith("/chat/completions") and "/openai/deployments/" not in path:
        path = path[: -len("/chat/completions")] + "/models"
    elif config.api_format == "anthropic" and path.endswith("/messages"):
        path = path[: -len("/messages")] + "/models"
    elif config.api_format == "gemini" and "/models/" in path:
        path = path[: path.index("/models/")] + "/models"
        url = url.copy_with(query=None)
    else:
        raise DestinationError("This service's model list cannot be found from its URL. Enter the model ID from the service instead.")
    return str(url.copy_with(path=path))


@app.post("/providers/{provider}/models")
async def provider_models_endpoint(provider: str, request: ProviderModelsRequest):
    """The models this API key can use, read from the provider's own model list."""
    if provider == "custom":
        config = request.custom_provider
        if not config:
            raise HTTPException(400, "Enter the custom model's connection details first.")
        name, style = config.name or "Custom model", config.api_format
        try:
            url = custom_models_url(config)
        except DestinationError as exc:
            raise HTTPException(400, str(exc)) from None
        headers = dict(config.extra_headers or {})
    elif provider in PROVIDER_MODEL_LISTS:
        name, style, url, headers = AI_PROVIDERS[provider][0], provider, PROVIDER_MODEL_LISTS[provider], {}
        if not (request.api_key or "").strip():
            raise HTTPException(400, f"Enter the {name} API key first.")
    else:
        raise HTTPException(404, "VEILUX cannot list models for this provider.")
    key = (request.api_key or "").strip()
    if key:
        if style in ("gemini",):
            headers["x-goog-api-key"] = key
        elif style in ("claude", "anthropic"):
            headers["x-api-key"] = key
        else:
            headers["Authorization"] = f"Bearer {key}"
    if style in ("claude", "anthropic"):
        headers.setdefault("anthropic-version", "2023-06-01")
    style = {"anthropic": "claude", "openai": "openai"}.get(style, style)

    models, params = [], {"pageSize": "1000"} if style == "gemini" else ({"limit": "1000"} if style == "claude" else {})
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
            for _ in range(MODEL_LIST_MAX_PAGES):
                response = await client.get(url, headers=headers, params=params)
                if response.status_code != 200:
                    failure = provider_failure(name, None, response)
                    if response.status_code == 404:
                        failure = HTTPException(502, f"{name} has no model list at this address (HTTP 404). Enter the model ID instead.")
                    raise failure
                try:
                    body = response.json()
                except ValueError:
                    raise HTTPException(502, f"{name}'s model list was not JSON.") from None
                models.extend(parse_model_list(style, body))
                if style == "gemini" and isinstance(body, dict) and body.get("nextPageToken"):
                    params = {"pageSize": "1000", "pageToken": str(body["nextPageToken"])}
                elif style == "claude" and isinstance(body, dict) and body.get("has_more") and body.get("last_id"):
                    params = {"limit": "1000", "after_id": str(body["last_id"])}
                else:
                    break
    except HTTPException:
        raise
    except Exception as exc:
        log.warning(f"Model list for {name} failed: {type(exc).__name__}")
        raise HTTPException(502, f"Could not read {name}'s model list. " + public_error(exc)) from None
    unique = {m["id"]: m for m in models}
    return {"provider": provider, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "count": len(unique), "models": sorted(unique.values(), key=lambda m: m["name"].lower())}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": VERSION}


class PairRequest(BaseModel):
    code: str = Field(max_length=64)


@app.post("/pair")
async def pair(request: Request, body: PairRequest):
    """Exchanges the pairing code shown at start-up for the backend key."""
    if not from_this_computer(request):
        raise HTTPException(403, "Pairing works only on the computer running the backend. From another computer, "
                                 "enter the backend's VEILUX_TOKEN value instead.")
    if not PAIRING["code"] or time.monotonic() > PAIRING["expires"] or PAIRING["failures"] >= MAX_PAIRING_FAILURES:
        raise HTTPException(410, "No pairing code is active. Restart the backend to get a new code.")
    given = re.sub(r"[\s-]", "", body.code).upper()
    if not hmac.compare_digest(given.encode("utf-8"), PAIRING["code"].encode("utf-8")):
        PAIRING["failures"] += 1
        left = MAX_PAIRING_FAILURES - PAIRING["failures"]
        raise HTTPException(401, "Wrong pairing code." + (f" {left} tries left." if left else
                                 " The code is now disabled; restart the backend to get a new one."))
    return {"token": ACCESS_TOKEN}


@app.get("/auth/check")
async def auth_check():
    """Answers only requests that carry the backend key (see only_the_extension)."""
    return {"paired": True}


def port_available(host: str, port: int) -> bool:
    """True if nothing else listens on this address. Checked before start-up,
    so a second copy explains itself instead of failing with a socket error."""
    try:
        family = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][0]
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            if os.name != "nt":
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((host, port))
        return True
    except OSError:
        return False


def _pause_before_closing():
    """A packaged backend opened by double-click on Windows runs in its own
    console window, which closes as soon as it exits: keep an error readable."""
    if getattr(sys, "frozen", False) and os.name == "nt" and sys.stdin and sys.stdin.isatty():
        try:
            input("Press Enter to close this window.")
        except (EOFError, KeyboardInterrupt):
            pass


def _open_pairing_window():
    try:
        code = prepare_access()
    except (OSError, ValueError) as exc:
        log.error(f"Backend key unavailable: {exc}")
        raise
    if os.environ.get("VEILUX_TOKEN"):
        print("🔑 Backend key: VEILUX_TOKEN. Enter it in Settings -> Backend, or pair with the code below.")
    else:
        print(f"🔑 Backend key: {os.path.abspath(KEY_FILE)}")
    print(f"🤝 Pairing code: {code}  (valid {PAIRING_CODE_SECONDS // 60} minutes, on this computer)")
    print("   Enter it in the extension under Settings -> Backend and choose Pair; this is needed once per browser.")


if __name__ == "__main__":
    import argparse
    import os
    import uvicorn
    parser = argparse.ArgumentParser(description="VEILUX backend")
    # Only this computer can reach the backend by default. Every request needs
    # the backend key, from the key file or VEILUX_TOKEN.
    parser.add_argument("--host", default=os.environ.get("VEILUX_HOST", "127.0.0.1"),
                        help="interface to listen on (default 127.0.0.1, or $VEILUX_HOST)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("VEILUX_PORT", "8000")),
                        help="port to listen on (default 8000, or $VEILUX_PORT)")
    parser.add_argument("--version", action="version", version=f"VEILUX backend {VERSION}")
    args = parser.parse_args()

    def stop(message: str, code: int = 1):
        print(message, file=sys.stderr, flush=True)
        _pause_before_closing()
        sys.exit(code)
    # VEILUX_LOG_LEVEL=DEBUG also shows each request's options; WARNING shows only problems.
    logging.basicConfig(level=os.environ.get("VEILUX_LOG_LEVEL", "INFO").upper(), format="[%(name)s] %(message)s")
    if args.host in ("0.0.0.0", "::"):
        if not ALLOWED_HOSTS:
            ANY_HOST = True
            print("⚠️  Listening on every interface: set VEILUX_ALLOWED_HOSTS to the names other computers use "
                  "for this backend, to also refuse requests that reach it under another name.")
    elif args.host.lower() not in LOOPBACK_HOSTS:
        ALLOWED_HOSTS.add(args.host.lower().strip("[]"))
    if ACCESS_TOKEN and len(ACCESS_TOKEN) < MIN_TOKEN_LENGTH:
        stop(f"⛔ Not starting: VEILUX_TOKEN must be at least {MIN_TOKEN_LENGTH} characters, for example the output of\n"
             "   python -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
             "   Or unset it: the backend then creates its own key.", 2)
    if not is_loopback_address(args.host):
        print("⚠️  Other computers can reach this backend. Every request needs its key; the backend serves plain "
              "HTTP, so use a trusted network or a TLS reverse proxy.")
    shown = "localhost" if args.host in ("127.0.0.1", "0.0.0.0") else args.host
    if not port_available(args.host, args.port):
        stop(f"⛔ Port {args.port} is already in use on {args.host}. Is VEILUX already running? "
             f"Stop the other copy, or start this one with --port <another port> and enter that address "
             "under Settings → Backend → Backend address.")
    print(f"🦉 VEILUX v{VERSION}")
    print(f"📡 http://{shown}:{args.port}")
    if args.port != 8000 or args.host not in ("127.0.0.1", "localhost"):
        print(f"   Set Settings → Backend → Backend address to http://{shown}:{args.port} in the extension.")
    if DATA_DIR:
        print(f"📁 Data folder: {DATA_DIR}")
    print("   Press Ctrl+C to stop.", flush=True)
    # uvicorn stops gracefully on these signals, then raises them again under
    # the handler that was there before. The default would end the process
    # with an error code after a clean stop (3 for Ctrl+Break on Windows, 143
    # for SIGTERM), so a clean stop exits with 0 instead.
    import signal

    def _stopped(*_):
        raise SystemExit(0)
    for name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stopped)
    try:
        uvicorn.run(app, host=args.host, port=args.port)
    except SystemExit as exc:
        # uvicorn exits this way when start-up fails (for example an unusable key file).
        if exc.code not in (0, None):
            _pause_before_closing()
        raise
