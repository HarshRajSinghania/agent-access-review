"""Turn agent configuration files into the normalized inventory model.

Two input formats are supported:

* MCP configs (Claude Desktop, Cursor, VS Code `.vscode/mcp.json`, ...). These carry no
  ownership or approval data, which is exactly what makes them "shadow agents".
* Agent manifests (`agents.yaml`), a governed format for LangChain / CrewAI / custom agents
  that records owner, approval, tools, credentials and usage.

Secrets are redacted here, before anything reaches the evidence store.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .model import Agent, Credential, Grant

CATALOG = yaml.safe_load((Path(__file__).parent / 'catalog.yaml').read_text(encoding='utf-8'))

REDACTED = '***REDACTED***'
SECRET_NAME = re.compile(r'TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|(^|_)PAT($|_)|AUTH', re.I)
SECRET_FLAG = re.compile(r'^(--?[\w-]*(?:token|secret|password|api-?key)[\w-]*)=(.+)$', re.I)
DSN_PASSWORD = re.compile(r'^([a-z][a-z0-9+.-]*://[^:/@\s]+:)([^@\s]+)(@)', re.I)
# docker flags that consume the next argument, so it is not mistaken for the image name
DOCKER_VALUE_FLAGS = {'-e', '--env', '-v', '--volume', '--name', '--network', '-p', '--publish',
                      '--mount', '--env-file', '-w', '--workdir', '-u', '--user', '--entrypoint'}


def is_reference(value: str) -> bool:
    """True when a secret field points at a secret store or env var instead of holding the secret."""
    v = str(value).strip()
    return (v == '' or '${' in v or v.startswith(('$', 'op://', 'vault:', 'secretsmanager:', 'env:', '{{'))
            or (v.startswith('<') and v.endswith('>')))


class ConfigError(ValueError):
    """A file in a supported format whose structure isn't what the format requires."""


def load(path: Path, source: str | None = None) -> list[Agent]:
    """Parse one file. Returns [] for files that are neither format. `source` is the path recorded
    in the inventory and evidence (defaults to the path as given). Raises ValueError (including
    ConfigError) or yaml.YAMLError for malformed input, never anything else."""
    try:
        return _load(path, source or path.as_posix())
    except (AttributeError, KeyError, TypeError, RecursionError) as e:
        # Wrong shapes (a list where an object belongs, a missing id, ...) and absurd nesting
        # are input problems, not crashes: report them like any other malformed file.
        raise ConfigError(f'unexpected structure ({type(e).__name__}: {e})') from e


def _strip_jsonc(text: str) -> str:
    """Strip // line comments, /* */ block comments and trailing commas from JSONC.
    Does not alter // inside strings. Suitable for VS Code mcp.json files."""
    out = []
    i = 0
    n = len(text)
    in_string = False
    escape = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        # line comment
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            i += 2
            while i < n and text[i] not in '\n\r':
                i += 1
            continue
        # block comment
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                i += 1
            i += 2  # skip */
            continue
        out.append(c)
        i += 1
    result = ''.join(out)
    # remove trailing commas before } or ]
    result = re.sub(r',(\s*[}\]])', r'\1', result)
    return result


def _load(path: Path, source: str) -> list[Agent]:
    text = path.read_text(encoding='utf-8')
    if path.suffix.lower() == '.json':
        text = _strip_jsonc(text)
        data = json.loads(text)
        servers = data.get('mcpServers', data.get('servers')) if isinstance(data, dict) else None
        if isinstance(servers, dict):
            return [parse_mcp_config(path, data, servers, source)]
    elif path.suffix.lower() in {'.yaml', '.yml'}:
        data = yaml.safe_load(text) or {}
        if isinstance(data, dict) and isinstance(data.get('agents'), list):
            return parse_manifest(path, data, source)
    return []
