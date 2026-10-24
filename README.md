# http-digest-auth-challenge

Parses `WWW-Authenticate: Digest` challenges and computes the `Authorization` header response per RFC 7616, supporting MD5 and SHA-256 (including the `-sess` variants) and `qop` of `auth` and `auth-int`.

## Usage

```python
from http_digest_auth_challenge import parse_challenge, build_authorization

challenge = parse_challenge(
    'Digest realm="api.example", nonce="abc123", qop="auth", algorithm=MD5'
)
header = build_authorization(
    challenge,
    username="alice",
    password="secret",
    method="GET",
    uri="/resource",
)
# header -> 'Digest username="alice", realm="api.example", nonce="abc123", ...'
```

Exported names: `parse_challenge`, `build_authorization`, `DigestChallenge`, `DigestError`.

## Why this exists

Handling HTTP Digest auth means parsing a challenge that may contain quoted strings with internal commas, computing a hash over a specific set of fields, and quoting the result back into a header. Doing this inline is error-prone and the edge cases (quoted commas, `-sess` A1 derivation, `auth-int` body hashing) are easy to get wrong.

This library exists to do exactly that, with zero dependencies beyond the standard library. The trade-off: it does not perform the HTTP request itself, manage a nonce-count cache across requests, or retry on `stale=true`. You call it once per challenge and wire the result into your own HTTP client.

## The awkward edge

The `qop` parameter is a quoted string that *contains commas* (e.g. `qop="auth,auth-int"`). A naive `split(",")` on the header will corrupt it. This library's parser respects quoted-string boundaries, so commas inside any quoted value are preserved.

## Determinism

`build_authorization` generates a client nonce (`cnonce`) internally when you don't pass one. The generated value is not deterministic, but the computation that uses it is — tests assert on the response hash for fixed inputs, not on the cnonce value itself. The `clock` argument is accepted for API symmetry and future extensions (e.g. nonce freshness checks) but does not affect the digest computation today.
