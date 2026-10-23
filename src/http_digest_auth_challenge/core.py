# http-digest-auth-challenge core

"""
Core parsing and digest computation for HTTP Digest Authentication (RFC 7616).

Design decisions
----------------
- The auth-param list is parsed with a regex that respects quoted strings.
  RFC 7235 grammar allows commas *inside* quoted-string values, so a naive
  str.split(',') is wrong. A single regex with a named capture for the token,
  an optional equals, and an optional quoted-or-token value handles every
  well-formed challenge this library has seen in practice.
- We accept unknown parameters (e.g. 'userhash', 'qop="auth,auth-int"') and
  store them verbatim rather than raising, because servers routinely emit
  extensions and the client only needs the subset it understands.
- The cnonce is generated with secrets.token_urlsafe(16). Non-determinism in
  the *value* of a nonce is not test-breaking because we never assert on the
  cnonce itself; we assert on the structure of the output and on the digest
  computed from inputs we control.
- build_authorization takes a clock function defaulting to time.time. This
  lets tests pass a fake clock for deterministic nc/nonce checks.
"""

from __future__ import annotations

import re
import time
import secrets
import hashlib
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


__all__ = [
    "DigestChallenge",
    "parse_challenge",
    "build_authorization",
    "DigestError",
]


class DigestError(ValueError):
    """Raised when a challenge cannot be parsed or a digest cannot be built."""


# auth-param = token "=" ( token / quoted-string )
# quoted-string permits commas inside, so we must not split on raw commas.
# This regex matches one key=value pair where the value may be a quoted
# string (with internal commas, equals, etc.) or a bare token.
_PARAM_RE = re.compile(
    r"""
    (?:^|\s*,\s*)          # field boundary: start or comma + optional ws
    ([A-Za-z][A-Za-z0-9!#$%^'*+\-.^_`|~]*)   # token: parameter name
    (?:=(["'\"]?)                          # optional equals + opening quote
        ([^,"'\"]*?(?:(?<!\\)["'\"])?)    # value content (quoted or token)
    )?                                    # value is optional (RFC says required,
                                          # but we tolerate missing for robustness)
    """,
    re.VERBOSE,
)


def _split_params(s: str) -> List[Tuple[str, str]]:
    """Split the parameter portion of a challenge into (name, value) pairs.

    Values that were quoted have their surrounding quotes stripped.
    A bare token value is returned as-is.
    """
    params: List[Tuple[str, str]] = []
    pos = 0
    n = len(s)
    while pos < n:
        # skip leading whitespace and stray commas
        while pos < n and (s[pos].isspace() or s[pos] == ","):
            pos += 1
        if pos >= n:
            break
        # read token
        start = pos
        while pos < n and re.match(r"[A-Za-z0-9!#$%^'*+\-.^_`|~]", s[pos]):
            pos += 1
        name = s[start:pos]
        if not name:
            # unparseable char, bail
            pos += 1
            continue
        # skip ws
        while pos < n and s[pos].isspace():
            pos += 1
        value = ""
        if pos < n and s[pos] == "=":
            pos += 1
            while pos < n and s[pos].isspace():
                pos += 1
            if pos < n and s[pos] in ("'", '"'):
                quote = s[pos]
                pos += 1
                vstart = pos
                # consume until matching unescaped quote
                while pos < n:
                    if s[pos] == quote and s[pos - 1] != "\\":
                        break
                    pos += 1
                value = s[vstart:pos]
                # unescape escaped quotes and backslashes
                value = value.replace(f"\\{quote}", quote).replace("\\\\", "\\")
                if pos < n and s[pos] == quote:
                    pos += 1
            else:
                vstart = pos
                while pos < n and re.match(r"[A-Za-z0-9!#$%^'*+\-.^_`|~]", s[pos]):
                    pos += 1
                value = s[vstart:pos]
        params.append((name, value))
    return params


@dataclass
class DigestChallenge:
    """A parsed Digest WWW-Authenticate challenge."""

    algorithm: str = "MD5"
    realm: str = ""
    nonce: str = ""
    opaque: Optional[str] = None
    qop: Optional[str] = None
    userhash: Optional[str] = None
    stale: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)
    raw_params: Dict[str, str] = field(default_factory=dict)

    @property
    def qop_list(self) -> List[str]:
        """Return qop split into a list, or an empty list if absent."""
        if not self.qop:
            return []
        return [q.strip() for q in self.qop.split(",") if q.strip()]


def parse_challenge(header_value: str) -> DigestChallenge:
    """Parse a WWW-Authenticate: Digest <...> header value.

    Raises DigestError if the scheme is not Digest or no nonce/realm present.
    """
    if header_value is None:
        raise DigestError("header value is None")
    stripped = header_value.strip()
    if not stripped:
        raise DigestError("empty header value")
    # Scheme is the leading token (RFC 7235: token = 1*tchar).
    # We match case-insensitively.
    space = stripped.find(" ")
    if space == -1:
        # Could be just 'Digest' with no params — still technically valid but
        # useless. We accept it and return defaults.
        scheme = stripped
        rest = ""
    else:
        scheme = stripped[:space]
        rest = stripped[space:].strip()

    if not scheme or scheme.lower() != "digest":
        raise DigestError(f"not a Digest challenge: scheme={scheme!r}")

    pairs = _split_params(rest)
    raw: Dict[str, str] = {}
    for name, value in pairs:
        raw[name.lower()] = value

    challenge = DigestChallenge(
        algorithm=raw.get("algorithm", "MD5"),
        realm=raw.get("realm", ""),
        nonce=raw.get("nonce", ""),
        opaque=raw.get("opaque"),
        qop=raw.get("qop"),
        userhash=raw.get("userhash"),
        stale=raw.get("stale"),
        raw_params=dict(raw),
    )

    if not challenge.nonce:
        raise DigestError("Digest challenge missing required 'nonce' parameter")
    if not challenge.realm:
        raise DigestError("Digest challenge missing required 'realm' parameter")

    return challenge


def _h(data: bytes, algorithm: str) -> str:
    """Hex digest of *data* using the named algorithm."""
    algo = algorithm.upper().replace("-", "")
    if algo in ("MD5", "MD5SESS"):
        return hashlib.md5(data).hexdigest()
    if algo in ("SHA256", "SHA256SESS"):
        return hashlib.sha256(data).hexdigest()
    if algo in ("SHA512256", "SHA512256SESS"):
        return hashlib.sha512(data).hexdigest()[:64]
    raise DigestError(f"unsupported algorithm: {algorithm!r}")


def _kd(secret: str, data: str, algorithm: str) -> str:
    """KD(secret, data) = H(secret:data)."""
    return _h(f"{secret}:{data}".encode("utf-8"), algorithm)


def build_authorization(
    challenge: DigestChallenge,
    username: str,
    password: str,
    method: str = "GET",
    uri: str = "/",
    body: bytes = b"",
    cnonce: Optional[str] = None,
    nc: int = 1,
    clock: Callable[[], float] = time.time,
) -> str:
    """Build an Authorization header value for a Digest challenge.

    Computes the response per RFC 7616. Supports MD5, SHA-256, and the
    '-sess' variants. Supports qop of 'auth' and 'auth-int'.

    Parameters
    ----------
    challenge:
        A DigestChallenge returned by parse_challenge.
    username:
        The username (already decoded, plain text).
    password:
        The password (plain text).
    method:
        HTTP method, e.g. "GET" or "POST".
    uri:
        The request URI (the effective path used in the digest).
    body:
        The request body bytes, used only for qop=auth-int.
    cnonce:
        Client nonce. If None, one is generated via secrets.token_urlsafe(16).
    nc:
        Nonce count as an integer. Will be zero-padded to 8 hex digits.
    clock:
        Clock function returning seconds since the epoch. Used only if the
        challenge lacks a nonce timestamp the caller wants to check — here
        it is accepted for API symmetry and testability but not currently
        used for computation. (Kept so that future extensions and tests can
        pass a fake clock without changing the signature.)
    """
    if not username:
        raise DigestError("username must be non-empty")
    if challenge.nonce is None or challenge.nonce == "":
        raise DigestError("challenge has no nonce")

    algorithm = challenge.algorithm or "MD5"
    algo_norm = algorithm.upper().replace("-", "")
    is_sess = algo_norm.endswith("SESS")
    if is_sess:
        algo_norm = algo_norm[:-4]
    if algo_norm not in ("MD5", "SHA256", "SHA512256"):
        raise DigestError(f"unsupported algorithm: {algorithm!r}")

    qop_list = challenge.qop_list
    qop: Optional[str] = None
    if qop_list:
        # Prefer auth; fall back to auth-int if that's all the server offers.
        if "auth" in qop_list:
            qop = "auth"
        elif "auth-int" in qop_list:
            qop = "auth-int"
        else:
            raise DigestError(f"no supported qop in: {challenge.qop!r}")

    if cnonce is None:
        cnonce = secrets.token_urlsafe(16)

    nc_hex = f"{nc:08x}"

    # A1 = username:realm:password
    # For -sess: A1 = H(username:realm:password):nonce:cnonce
    a1_base = f"{username}:{challenge.realm}:{password}"
    if is_sess:
        a1 = f"{_h(a1_base.encode('utf-8'), algorithm)}:{challenge.nonce}:{cnonce}"
    else:
        a1 = a1_base

    # A2 = method:uri  (for auth)
    # A2 = method:uri:H(body)  (for auth-int)
    if qop == "auth-int":
        body_hash = _h(body, algorithm)
        a2 = f"{method}:{uri}:{body_hash}"
    else:
        a2 = f"{method}:{uri}"

    ha1 = _h(a1.encode("utf-8"), algorithm)
    ha2 = _h(a2.encode("utf-8"), algorithm)

    if qop:
        response = _kd(ha1, f"{challenge.nonce}:{nc_hex}:{cnonce}:{qop}:{ha2}", algorithm)
    else:
        response = _kd(ha1, f"{challenge.nonce}:{ha2}", algorithm)

    # Assemble the header. RFC 7616 requires quoting of most values.
    parts: List[str] = [
        f'username="{username}"',
        f'realm="{challenge.realm}"',
        f'nonce="{challenge.nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
        f'algorithm={algorithm}',
    ]
    if qop:
        parts.append(f'qop={qop}')
        parts.append(f'nc={nc_hex}')
        parts.append(f'cnonce="{cnonce}"')
    if challenge.opaque:
        parts.append(f'opaque="{challenge.opaque}"')
    if challenge.userhash:
        parts.append(f'userhash={challenge.userhash}')

    return "Digest " + ", ".join(parts)
