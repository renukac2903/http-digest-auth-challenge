# http-digest-auth-challenge
# Parses Digest WWW-Authenticate challenges and computes response digests.

"""
http-digest-auth-challenge
=========================

Parses Digest WWW-Authenticate challenges and computes response digests
with MD5 or SHA-256 per RFC 7616.
"""

from http_digest_auth_challenge.core import (
    DigestChallenge,
    parse_challenge,
    build_authorization,
    DigestError,
)

__all__ = [
    "DigestChallenge",
    "parse_challenge",
    "build_authorization",
    "DigestError",
]
