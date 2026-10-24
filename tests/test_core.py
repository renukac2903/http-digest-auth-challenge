# tests for http-digest-auth-challenge

"""
Test suite for http-digest-auth-challenge.

Determinism: we never assert on wall-clock time and never sleep. The cnonce
is generated internally but we never assert on its value; we assert on the
structure of the output and on the digest computed from fixed inputs.
"""

import unittest

from http_digest_auth_challenge import (
    DigestChallenge,
    parse_challenge,
    build_authorization,
    DigestError,
)


class ParseChallengeTests(unittest.TestCase):
    """Tests for parse_challenge."""

    def test_parses_basic_challenge(self):
        hdr = 'Digest realm="testrealm@host.com", nonce="abc123", algorithm=MD5'
        c = parse_challenge(hdr)
        self.assertEqual(c.realm, "testrealm@host.com")
        self.assertEqual(c.nonce, "abc123")
        self.assertEqual(c.algorithm, "MD5")

    def test_parses_qop_with_multiple_values(self):
        hdr = 'Digest realm="r", nonce="n", qop="auth,auth-int"'
        c = parse_challenge(hdr)
        self.assertEqual(c.qop, "auth,auth-int")
        self.assertEqual(c.qop_list, ["auth", "auth-int"])

    def test_parses_opaque(self):
        hdr = 'Digest realm="r", nonce="n", opaque="0xdeadbeef"'
        c = parse_challenge(hdr)
        self.assertEqual(c.opaque, "0xdeadbeef")

    def test_parses_sha256_algorithm(self):
        hdr = 'Digest realm="r", nonce="n", algorithm=SHA-256'
        c = parse_challenge(hdr)
        self.assertEqual(c.algorithm, "SHA-256")

    def test_preserves_unknown_params_in_extra(self):
        # userhash is a known param but we also accept unknown ones in raw_params.
        hdr = 'Digest realm="r", nonce="n", custom-ext="hello"'
        c = parse_challenge(hdr)
        self.assertEqual(c.raw_params.get("custom-ext"), "hello")

    def test_quoted_value_with_internal_comma(self):
        # qop is quoted and contains a comma; must not be split.
        hdr = 'Digest realm="r", nonce="n", qop="auth,auth-int"'
        c = parse_challenge(hdr)
        self.assertEqual(c.qop, "auth,auth-int")

    def test_realm_with_internal_spaces(self):
        hdr = 'Digest realm="My Realm Here", nonce="n"'
        c = parse_challenge(hdr)
        self.assertEqual(c.realm, "My Realm Here")

    def test_missing_nonce_raises(self):
        hdr = 'Digest realm="r"'
        with self.assertRaises(DigestError):
            parse_challenge(hdr)

    def test_missing_realm_raises(self):
        hdr = 'Digest nonce="n"'
        with self.assertRaises(DigestError):
            parse_challenge(hdr)

    def test_non_digest_scheme_raises(self):
        hdr = 'Basic realm="r"'
        with self.assertRaises(DigestError):
            parse_challenge(hdr)

    def test_case_insensitive_scheme(self):
        hdr = 'digest realm="r", nonce="n"'
        c = parse_challenge(hdr)
        self.assertEqual(c.nonce, "n")

    def test_empty_header_raises(self):
        with self.assertRaises(DigestError):
            parse_challenge("")

    def test_challenge_with_stale(self):
        hdr = 'Digest realm="r", nonce="n", stale=true'
        c = parse_challenge(hdr)
        self.assertEqual(c.stale, "true")


class BuildAuthorizationTests(unittest.TestCase):
    """Tests for build_authorization."""

    def setUp(self):
        # A canonical RFC 2617-style challenge for MD5.
        self.challenge = parse_challenge(
            'Digest realm="testrealm@host.com", '
            'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
            'qop="auth", algorithm=MD5'
        )
        self.username = "Mufasa"
        self.password = "Circle Of Life"

    def test_response_for_md5_auth_matches_known_vector(self):
        # Known vector from RFC 7616 Appendix A.1 (MD5, qop=auth).
        auth = build_authorization(
            self.challenge,
            username=self.username,
            password=self.password,
            method="GET",
            uri="/dir/index.html",
            cnonce="0a4f113b",
            nc=1,
        )
        # The expected response hash for this exact input.
        # H(A1) = H("Mufasa:testrealm@host.com:Circle Of Life")
        # H(A2) = H("GET:/dir/index.html")
        # response = KD(H(A1), nonce:nc:cnonce:qop:H(A2))
        import hashlib
        ha1 = hashlib.md5(
            b"Mufasa:testrealm@host.com:Circle Of Life"
        ).hexdigest()
        ha2 = hashlib.md5(b"GET:/dir/index.html").hexdigest()
        expected = hashlib.md5(
            f"{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:{ha2}".encode()
        ).hexdigest()
        self.assertIn(f'response="{expected}"', auth)

    def test_header_starts_with_digest(self):
        auth = build_authorization(
            self.challenge,
            username=self.username,
            password=self.password,
            method="GET",
            uri="/dir/index.html",
            cnonce="0a4f113b",
        )
        self.assertTrue(auth.startswith("Digest "))

    def test_nc_is_zero_padded_to_8_hex(self):
        auth = build_authorization(
            self.challenge,
            username=self.username,
            password=self.password,
            method="GET",
            uri="/dir/index.html",
            cnonce="0a4f113b",
            nc=1,
        )
        self.assertIn("nc=00000001", auth)

    def test_includes_required_fields(self):
        auth = build_authorization(
            self.challenge,
            username=self.username,
            password=self.password,
            method="GET",
            uri="/dir/index.html",
            cnonce="0a4f113b",
        )
        self.assertIn('username="Mufasa"', auth)
        self.assertIn('realm="testrealm@host.com"', auth)
        self.assertIn('nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"', auth)
        self.assertIn('uri="/dir/index.html"', auth)
        self.assertIn('algorithm=MD5', auth)
        self.assertIn('qop=auth', auth)
        self.assertIn('cnonce="0a4f113b"', auth)

    def test_opaque_included_when_present(self):
        challenge = parse_challenge(
            'Digest realm="r", nonce="n", opaque="0xabc", qop="auth"'
        )
        auth = build_authorization(
            challenge,
            username="u",
            password="p",
            method="GET",
            uri="/",
            cnonce="c",
        )
        self.assertIn('opaque="0xabc"', auth)

    def test_sha256_digest_matches_known_vector(self):
        challenge = parse_challenge(
            'Digest realm="http-auth@example.org", '
            'nonce="7yp2x9jV8115f7ab7ab9j2k7a0k2l3m4n5o6p1q2r3s4t5u6v7w8x9y0z1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p", '
            'algorithm=SHA-256, qop="auth"'
        )
        auth = build_authorization(
            challenge,
            username="Mufasa",
            password="Circle Of Life",
            method="GET",
            uri="/dir/index.html",
            cnonce="0a4f113b",
            nc=1,
        )
        import hashlib
        ha1 = hashlib.sha256(
            b"Mufasa:http-auth@example.org:Circle Of Life"
        ).hexdigest()
        ha2 = hashlib.sha256(b"GET:/dir/index.html").hexdigest()
        expected = hashlib.sha256(
            f"{ha1}:7yp2x9jV8115f7ab7ab9j2k7a0k2l3m4n5o6p1q2r3s4t5u6v7w8x9y0z1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p:00000001:0a4f113b:auth:{ha2}".encode()
        ).hexdigest()
        self.assertIn(f'response="{expected}"', auth)

    def test_auth_int_includes_body_hash(self):
        challenge = parse_challenge(
            'Digest realm="r", nonce="n", qop="auth-int", algorithm=MD5'
        )
        auth = build_authorization(
            challenge,
            username="u",
            password="p",
            method="POST",
            uri="/api",
            body=b'hello=world',
            cnonce="c",
        )
        self.assertIn("qop=auth-int", auth)
        # verify the body hash was computed.
        import hashlib
        body_hash = hashlib.md5(b'hello=world').hexdigest()
        ha1 = hashlib.md5(b"u:r:p").hexdigest()
        ha2 = hashlib.md5(f"POST:/api:{body_hash}".encode()).hexdigest()
        expected = hashlib.md5(
            f"{ha1}:n:00000001:c:auth-int:{ha2}".encode()
        ).hexdigest()
        self.assertIn(f'response="{expected}"', auth)

    def test_sess_algorithm_uses_nonce_and_cnonce_in_a1(self):
        challenge = parse_challenge(
            'Digest realm="r", nonce="n", algorithm=MD5-sess, qop="auth"'
        )
        auth = build_authorization(
            challenge,
            username="u",
            password="p",
            method="GET",
            uri="/",
            cnonce="cn",
            nc=1,
        )
        import hashlib
        ha1_base = hashlib.md5(b"u:r:p").hexdigest()
        a1 = f"{ha1_base}:n:cn"
        ha1 = hashlib.md5(a1.encode()).hexdigest()
        ha2 = hashlib.md5(b"GET:/").hexdigest()
        expected = hashlib.md5(
            f"{ha1}:n:00000001:cn:auth:{ha2}".encode()
        ).hexdigest()
        self.assertIn(f'response="{expected}"', auth)

    def test_generated_cnonce_present_when_not_supplied(self):
        auth = build_authorization(
            self.challenge,
            username=self.username,
            password=self.password,
            method="GET",
            uri="/dir/index.html",
        )
        # cnonce must be present and quoted; we don't assert on its value.
        self.assertRegex(auth, r'cnonce="[^"]+"')

    def test_unsupported_algorithm_raises(self):
        challenge = parse_challenge(
            'Digest realm="r", nonce="n", algorithm=ROT13'
        )
        with self.assertRaises(DigestError):
            build_authorization(
                challenge,
                username="u",
                password="p",
                method="GET",
                uri="/",
            )

    def test_unsupported_qop_raises(self):
        challenge = parse_challenge(
            'Digest realm="r", nonce="n", qop="weird"'
        )
        with self.assertRaises(DigestError):
            build_authorization(
                challenge,
                username="u",
                password="p",
                method="GET",
                uri="/",
            )

    def test_empty_username_raises(self):
        with self.assertRaises(DigestError):
            build_authorization(
                self.challenge,
                username="",
                password="p",
                method="GET",
                uri="/",
            )

    def test_no_qop_uses_legacy_formula(self):
        challenge = parse_challenge(
            'Digest realm="r", nonce="n", algorithm=MD5'
        )
        auth = build_authorization(
            challenge,
            username="u",
            password="p",
            method="GET",
            uri="/",
        )
        import hashlib
        ha1 = hashlib.md5(b"u:r:p").hexdigest()
        ha2 = hashlib.md5(b"GET:/").hexdigest()
        expected = hashlib.md5(f"{ha1}:n:{ha2}".encode()).hexdigest()
        self.assertIn(f'response="{expected}"', auth)
        # no qop/nc/cnonce fields when qop absent
        self.assertNotIn("qop=", auth)
        self.assertNotIn("nc=", auth)


class IntegrationTests(unittest.TestCase):
    """Round-trip parsing + building."""

    def test_roundtrip_preserves_opaque_and_algorithm(self):
        hdr = (
            'Digest realm="api.example", nonce="xyz789", '
            'opaque="token-123", algorithm=SHA-256, qop="auth"'
        )
        c = parse_challenge(hdr)
        auth = build_authorization(
            c,
            username="alice",
            password="secret",
            method="POST",
            uri="/v1/data",
            cnonce="client-nonce",
            nc=5,
        )
        self.assertIn('opaque="token-123"', auth)
        self.assertIn('algorithm=SHA-256', auth)
        self.assertIn('nc=00000005', auth)
        self.assertIn('uri="/v1/data"', auth)


if __name__ == "__main__":
    unittest.main()
