"""OIDC/JWT verification with issuer, audience, JWKS, and time checks."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings

ASYMMETRIC_JWT_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"})


class IdentityError(ValueError):
    """Raised for an invalid or unverifiable bearer token."""


@dataclass(frozen=True, slots=True)
class Identity:
    subject: str
    issuer: str
    audience: tuple[str, ...]
    email: str | None = None
    display_name: str | None = None


def _decode_segment(segment: str) -> dict[str, Any]:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityError("malformed JWT segment") from exc


def parse_unverified_claims(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read header and payload for key selection; never treats them as trusted."""

    parts = token.split(".")
    if len(parts) != 3:
        raise IdentityError("malformed JWT")
    return _decode_segment(parts[0]), _decode_segment(parts[1])


def _audience_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise IdentityError("invalid JWT audience")


class JwksCache:
    def __init__(self, url: str, *, ttl_seconds: int = 300, client: httpx.AsyncClient | None = None) -> None:
        self.url = url
        self.ttl_seconds = ttl_seconds
        self.client = client
        self._keys: dict[str, dict[str, Any]] = {}
        self._expires_at = 0.0

    async def _refresh(self) -> None:
        own_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=5.0, follow_redirects=False)
        try:
            response = await client.get(self.url)
            response.raise_for_status()
            payload = response.json()
            keys = payload.get("keys")
            if not isinstance(keys, list):
                raise IdentityError("OIDC JWKS response has no keys")
            self._keys = {key["kid"]: key for key in keys if isinstance(key, dict) and isinstance(key.get("kid"), str)}
            self._expires_at = time.monotonic() + self.ttl_seconds
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise IdentityError("unable to fetch OIDC signing keys") from exc
        finally:
            if own_client:
                await client.aclose()

    async def get(self, kid: str) -> dict[str, Any]:
        if time.monotonic() >= self._expires_at:
            await self._refresh()
        key = self._keys.get(kid)
        if key is None:
            await self._refresh()
            key = self._keys.get(kid)
        if key is None:
            raise IdentityError("JWT signing key not found")
        return key


class OidcVerifier:
    def __init__(self, settings: Settings, *, jwks: JwksCache | None = None) -> None:
        if not settings.oidc_issuer or not settings.oidc_audience or not settings.oidc_jwks_url:
            raise ValueError("OIDC verifier requires issuer, audience, and JWKS URL")
        if not settings.oidc_algorithms or not set(settings.oidc_algorithms).issubset(ASYMMETRIC_JWT_ALGORITHMS):
            raise ValueError("OIDC verifier only allows asymmetric JWT algorithms")
        self.settings = settings
        self.jwks = jwks or JwksCache(settings.oidc_jwks_url)

    async def verify(self, token: str) -> Identity:
        try:
            import jwt
        except ImportError as exc:
            raise IdentityError("PyJWT[crypto] is required for OIDC verification") from exc
        try:
            header, _ = parse_unverified_claims(token)
            algorithm = header.get("alg")
            kid = header.get("kid")
            if algorithm not in self.settings.oidc_algorithms or not isinstance(kid, str):
                raise IdentityError("JWT algorithm or key id is not allowed")
            jwk = await self.jwks.get(kid)
            if jwk.get("alg") and jwk["alg"] != algorithm:
                raise IdentityError("JWT key algorithm mismatch")
            if jwk.get("use") not in (None, "sig") or (jwk.get("key_ops") and "verify" not in jwk["key_ops"]):
                raise IdentityError("JWT key is not valid for signature verification")
            signing_key = jwt.PyJWK.from_dict(jwk).key
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=list(self.settings.oidc_algorithms),
                audience=self.settings.oidc_audience,
                issuer=self.settings.oidc_issuer,
                leeway=self.settings.oidc_clock_skew_seconds,
                options={"require": ["sub", "iss", "aud", "exp"]},
            )
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError("JWT verification failed") from exc
        subject = payload.get("sub")
        issuer = payload.get("iss")
        if not isinstance(subject, str) or not subject or not isinstance(issuer, str):
            raise IdentityError("JWT subject or issuer is invalid")
        return Identity(
            subject=subject,
            issuer=issuer,
            audience=_audience_tuple(payload.get("aud")),
            email=payload.get("email") if isinstance(payload.get("email"), str) else None,
            display_name=payload.get("name") if isinstance(payload.get("name"), str) else None,
        )
